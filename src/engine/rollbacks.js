/*
 * rollbacks.js — WR.rollbacks(hctx) → Rollback[] (recommended first, then by time to recover)
 *
 * Turns the ranked hypotheses plus what the Helm output tells us (release, revisions, the exact
 * before/after of each change) into mitigation options with copyable commands. Rules (SPEC §4):
 *   helm-rollback     previous revision known            helm rollback REL PREV -n NS --kube-context C --wait --timeout 5m
 *   rollout-undo      image-only release, or a ReplicaSet rollout with no Helm release
 *   set-image         an image change whose old reference is known
 *   resource-restore  a limit decrease behind an OOM / throttling hypothesis
 *   config-revert     a ConfigMap / env / Secret change a hypothesis cites
 *   traffic-shift     ≥ 2 clusters, only some failing (templates with <…> placeholders)
 *   canary-abort      an Argo Rollouts Rollout in the release
 *   scale             a connection-exhaustion hypothesis driven by a replica/HPA increase
 *   roll-forward      the cause is not a change (certificate expiry) or a migration hook ran
 *   restart           stop-gap only
 * Exactly one option is recommended: the most preferred kind among those that fix the top
 * hypothesis (order in PREFERENCE; a high-risk option drops behind the safer kinds).
 *
 * Commands that change the cluster always name the context: the stated cluster, or the
 * placeholder <kube-context> when the paste never said which cluster it came from.
 * Time-to-recover figures are rough estimates for a small Deployment (pods restart and pass
 * readiness in a few minutes); they are labelled as estimates in the UI.
 */
(function (WR) {
  'use strict';

  var H = function () { return WR.hypotheses; };
  var PREFERENCE = ['canary-abort', 'helm-rollback', 'config-revert', 'rollout-undo', 'set-image', 'resource-restore', 'scale', 'roll-forward', 'traffic-shift', 'restart'];
  var RISK_RANK = { low: 0, medium: 1, high: 2 };
  var ETA = { 'helm-rollback': 6, 'rollout-undo': 4, 'set-image': 4, 'resource-restore': 5, 'config-revert': 5, scale: 5, 'canary-abort': 2, 'traffic-shift': 10, 'roll-forward': 15, restart: 3 };

  function ctxName(o) { return o && o.clusterKnown && o.cluster ? o.cluster : '<kube-context>'; }
  // kubectl prefix for commands that change something: always explicit about the cluster.
  function kx(o, ns) { return 'kubectl --context ' + ctxName(o) + (ns ? ' -n ' + ns : ''); }
  function kindRef(kind, name) {
    var k = String(kind || 'Deployment').toLowerCase();
    if (!/^(deployment|statefulset|daemonset)$/.test(k)) k = 'deployment';
    return k + '/' + name;
  }
  function containerOf(field) { var m = /containers\[([^\]]+)\]/.exec(field || ''); return m ? m[1] : null; }
  function envName(field) { var m = /env\[([^\]]+)\]/.exec(field || ''); return m ? m[1] : null; }
  function quote(s, n) { return '"' + WR.truncate(String(s || '').replace(/\s+/g, ' ').trim(), n || 120) + '"'; }

  // Argo CD or Flux re-applies the Git state within minutes and undoes a hand-made rollback or patch.
  function gitopsCaveat(release, ns, what) {
    return 'If Argo CD or Flux manages this release, pause auto-sync first (argocd app set <app> --sync-policy none, or flux suspend helmrelease ' +
      (release || '<name>') + ' -n ' + (ns || '<namespace>') + '), or it will ' + (what || 're-apply the Git version') + ' within minutes.';
  }

  function citedChangeIds(hyp) {
    return hyp.evidence.map(function (e) { return e.changeId; }).filter(Boolean);
  }
  // Changes a hypothesis rests on (weight ≥ 0.2), as opposed to ones it mentions in passing
  // ("also changed: …"). Only these may spawn a targeted revert or count as fixed by one.
  var PRIMARY_WEIGHT = 0.2;
  function primaryChangeIds(hyp) {
    return hyp.evidence.filter(function (e) { return e.changeId && e.weight >= PRIMARY_WEIGHT; }).map(function (e) { return e.changeId; });
  }

  function rollbacks(h) {
    var hyps = h.hypotheses || [];
    var top = hyps[0] || null;
    var out = [];
    var changeById = {};
    h.changes.forEach(function (c) { changeById[c.id] = c; });
    // Releases the pasted history shows were already rolled back: their changes are no longer live.
    // No option may re-apply them ("roll back to the previous revision" from the rollback row would
    // re-apply the bad upgrade) or revert them a second time.
    var rolledBackRel = {};
    (h.deploys || []).forEach(function (d) { if (d.rolledBack && d.release) rolledBackRel[d.release] = d; });
    function rolledBackChange(c) { return !!(c && c.release && rolledBackRel[c.release]); }
    var failingClusters = h.clusters.filter(function (c) { return c.status === 'failing'; }).map(function (c) { return c.name; });
    var healthyClusters = h.clusters.filter(function (c) { return c.status === 'healthy'; }).map(function (c) { return c.name; });
    // Datastores that clients in more than one cluster call (cross-cluster edges), when those
    // clusters include all of `clusters`. Empty when each cluster has its own database.
    function sharedStores(clusters) {
      return h.compList.filter(function (ds) {
        if (ds.type !== 'datastore') return false;
        var callers = (h.edgesTo[ds.id] || []).map(function (e) { return h.comps[e.from]; }).filter(Boolean);
        var cls = WR.uniq(callers.map(function (c) { return c.cluster; }));
        return cls.length > 1 && clusters.every(function (cl) { return cls.indexOf(cl) >= 0; });
      });
    }

    function add(r) {
      r.id = 'rb-' + WR.hash(r.kind + '|' + r._key);
      if (out.some(function (x) { return x.id === r.id; })) return;
      r.etaMinutes = r.etaMinutes != null ? r.etaMinutes : ETA[r.kind];
      r.fixes = WR.uniq(r.fixes || []);
      r.caveats = r.caveats || [];
      r.prerequisites = r.prerequisites || [];
      out.push(r);
    }
    // Azure Kubernetes Service (AKS) node names ("aks-<pool>-<id>-vmss…"): CoreDNS there is a managed
    // add-on, so hand edits to its ConfigMap or Deployment do not stick.
    function managedDns(comp) {
      var aks = h.compList.some(function (c) { return c.type === 'node' && c.cluster === comp.cluster && /^aks-/.test(c.name); });
      return aks ? 'The node names look like Azure Kubernetes Service (AKS), where CoreDNS is a managed add-on: change it through the coredns-custom ConfigMap, because edits to the coredns ConfigMap and Deployment are reconciled away.' : null;
    }
    function fixesFor(pred) { return hyps.filter(pred).map(function (x) { return x.id; }); }

    // ---- helm-rollback ----------------------------------------------------------------------------
    h.deploys.forEach(function (d) {
      if (!d.release || d.previousRevision == null || d.rolledBack) return;
      var comp = d.componentId ? h.comps[d.componentId] : null;
      var rel = h.changes.filter(function (c) { return c.release === d.release; });
      var relIds = rel.map(function (c) { return c.id; });
      var ns = d.namespace || (comp && comp.namespace) || '<namespace>';
      var ctx = ctxName(d);
      var cmds = ['helm rollback ' + d.release + ' ' + d.previousRevision + ' -n ' + ns + ' --kube-context ' + ctx + ' --wait --timeout 5m'];
      var argo = comp ? rel.filter(function (c) { return c.resourceKind === 'Rollout' && c.componentId === comp.id; })[0] : null;
      // Every failing workload the release touches in this cluster, so the rollback is verified
      // where it matters (an image tag in shared values breaks more than one Deployment).
      var watch = [];
      if (comp && comp.type !== 'external' && comp.type !== 'node') watch.push(comp);
      rel.forEach(function (c) {
        var w = h.comps[c.componentId];
        if (!w || watch.indexOf(w) >= 0 || w.type !== 'service' || w.cluster !== (comp ? comp.cluster : d.cluster)) return;
        if (w.status === 'failing' || w.status === 'root' || w.status === 'degraded') watch.push(w);
      });
      // An Argo Rollout is not a Deployment: `kubectl rollout status` cannot watch it.
      if (argo) cmds.push('kubectl argo rollouts status ' + argo.resourceName + ' -n ' + (argo.namespace || comp.namespace) + ' --context ' + ctx);
      else watch.forEach(function (w) { cmds.push(kx(d, w.namespace) + ' rollout status ' + H().workloadRef(w) + ' --timeout=5m'); });
      var caveats = [], prereq = [];
      var risk = 'low';
      if (d.revision != null) caveats.push('Helm records the rollback as a new revision (r' + (d.revision + 1) + ') with the contents of r' + d.previousRevision + '; r' + d.revision + ' stays in the history.');
      // CRDs and hooks are not reverted (caveats below), so they are not in the "reverts" list.
      var notable = rel.filter(function (c) { return c.risk !== 'low' && c.category !== 'crd' && c.category !== 'migration-hook'; });
      if (notable.length > 1) caveats.push('It reverts all of r' + (d.revision != null ? d.revision : 'the release') + '\'s template changes, not only the suspect one: ' + notable.slice(0, 4).map(function (c) { return c.summary; }).join('; ') + (notable.length > 4 ? '; and ' + (notable.length - 4) + ' more' : '') + '.');
      var crds = WR.uniq(rel.filter(function (c) { return c.category === 'crd'; }).map(function (c) { return c.resourceName; }));
      if (crds.length) {
        caveats.push('Helm does not upgrade or roll back CRDs kept in a chart\'s crds/ directory; if ' + crds.join(', ') + ' came from there, its change stays in place.');
        risk = 'medium';
      }
      var mig = rel.filter(function (c) { return c.category === 'migration-hook'; })[0];
      if (mig) {
        caveats.push('The migration hook in r' + d.revision + ' (' + (mig.resourceName || 'Job') + ') already ran; rollback does not reverse it, so the database schema stays at the new version. Confirm r' + d.previousRevision + '\'s code works with that schema first.');
        caveats.push('Rollback runs the chart\'s pre-rollback and post-rollback hooks if it defines any; upgrade hooks do not run again.');
        risk = 'high';
      }
      if (rel.some(function (c) { return c.category === 'secret'; }) && risk === 'low') risk = 'medium';
      var cmChanges = rel.filter(function (c) { return c.category === 'configmap' && c.risk !== 'low'; });
      var templateChange = rel.some(function (c) { return /^(image|env|resources|probe)$/.test(c.category); });
      if (cmChanges.length && !templateChange && comp) caveats.push('Pods that read ConfigMap ' + cmChanges[0].resourceName + ' as environment variables keep the new values until they restart; this rollback does not change the pod template, so follow with: ' + kx(d, comp.namespace) + ' rollout restart ' + H().workloadRef(comp));
      if (d.status && /failed/i.test(d.status)) caveats.push('r' + d.revision + ' is marked ' + d.status + '; rolling back to r' + d.previousRevision + ' restores the last successful release.');
      var alsoIn = [];
      if (comp) {
        var otherFailing = h.compList.filter(function (c) { return c.name === comp.name && c.cluster !== comp.cluster && (c.status === 'failing' || c.status === 'root' || c.status === 'degraded'); });
        WR.uniq(otherFailing.map(function (c) { return c.cluster; })).forEach(function (cl) {
          // The Helm pane says the same release revision runs there too: roll it back there as well.
          var sib = (h.helmSiblings || []).filter(function (x) {
            return x.cluster === cl && x.revision === d.revision && (!x.release || x.release === d.release);
          })[0];
          if (sib && d.revision != null) {
            alsoIn.push(cl);
            cmds.push('helm rollback ' + d.release + ' ' + d.previousRevision + ' -n ' + ns + ' --kube-context ' + cl + ' --wait --timeout 5m');
            otherFailing.filter(function (c) { return c.cluster === cl && c.type === 'service'; }).forEach(function (c) {
              cmds.push('kubectl --context ' + cl + ' -n ' + c.namespace + ' rollout status ' + H().workloadRef(c) + ' --timeout=5m');
            });
            prereq.push('Confirm ' + cl + ' runs ' + d.release + ' r' + d.revision + ' (Helm pane line ' + sib.line + ' says so) before its steps: helm history ' + d.release + ' -n ' + ns + ' --kube-context ' + cl + ' --max 5');
            return;
          }
          caveats.push('Only ' + (d.cluster || 'one cluster') + '\'s release history was pasted. If ' + cl + ' also runs ' + d.release + ' r' + d.revision + ', roll it back there too.');
          prereq.push('Check ' + cl + ': helm history ' + d.release + ' -n ' + ns + ' --kube-context ' + cl + ' --max 5');
        });
        // Clusters whose clients share one database: rolling back only one of them leaves the
        // others' connections in place.
        var covered = WR.uniq([comp.cluster].concat(alsoIn));
        var shared = sharedStores(covered);
        if (shared.length) {
          var users = WR.uniq((h.edgesTo[shared[0].id] || []).map(function (e) { return h.comps[e.from] && h.comps[e.from].cluster; }).filter(Boolean)).sort();
          caveats.push(users.join(' and ') + ' use one database (' + shared[0].name + ' in ' + shared[0].cluster + '), and every cluster\'s connections count against its limit, so rolling back only one cluster is not enough.');
        }
        var siblingsOk = h.compList.filter(function (c) { return c.name === comp.name && c.cluster !== comp.cluster && c.status === 'healthy'; }).map(function (c) { return c.cluster; });
        if (siblingsOk.length) caveats.push('Hold the rollout of ' + d.release + ' r' + d.revision + ' to ' + WR.uniq(siblingsOk).join(', ') + ' (healthy there) until the cause is fixed.');
      }
      prereq.unshift('Check that r' + d.previousRevision + ' ran without problems before r' + (d.revision != null ? d.revision : 'the upgrade') + ': helm history ' + d.release + ' -n ' + ns + ' --kube-context ' + ctx + ' --max 5');
      prereq.unshift('Access to kube-context ' + ctx + (alsoIn.length ? ' and ' + alsoIn.join(' and ') : '') + ' with rights to change namespace ' + ns + '.');
      if (d.previousRevisionAssumed) prereq.push('r' + d.previousRevision + ' is assumed to be the previous revision (helm list shows only the latest).');
      caveats.push(gitopsCaveat(d.release, ns, 're-apply r' + (d.revision != null ? d.revision : 'the new revision')));
      var where = d.clusterKnown && d.cluster ? [d.cluster].concat(alsoIn) : [];
      add({
        _key: d.release + '|' + d.cluster + '|' + d.previousRevision, kind: 'helm-rollback',
        title: 'Roll back Helm release ' + d.release + ' to r' + d.previousRevision + (where.length ? ' in ' + where.join(' and ') : ''),
        commands: cmds, risk: risk, etaMinutes: mig ? 8 : 6,
        fixes: fixesFor(function (x) {
          if (x._release === d.release) return true;
          if (x.category === 'bad-deploy' && x.componentId === d.componentId) return true;
          return primaryChangeIds(x).some(function (id) { return relIds.indexOf(id) >= 0; });
        }),
        caveats: caveats, prerequisites: prereq
      });
    });

    // ---- resource-restore -------------------------------------------------------------------------
    hyps.forEach(function (x) {
      if (x.category !== 'resource-limits') return;
      var cut = primaryChangeIds(x).map(function (id) { return changeById[id]; }).filter(function (c) { return c && c.category === 'resources' && /limits\.(memory|cpu)$/.test(c.field || '') && c.direction === 'down'; })[0];
      if (!cut || cut.before == null || rolledBackChange(cut)) return;
      var comp = h.comps[cut.componentId] || h.comps[x.componentId];
      var res = /limits\.(memory|cpu)$/.exec(cut.field)[1];
      var req = h.changes.filter(function (c) { return c.componentId === cut.componentId && c.category === 'resources' && new RegExp('requests\\.' + res + '$').test(c.field || '') && c.before != null && c.resourceName === cut.resourceName; })[0];
      var ctr = containerOf(cut.field) || (comp ? comp.name : cut.resourceName);
      var ref = kindRef(cut.resourceKind, cut.resourceName);
      var ns = cut.namespace || (comp && comp.namespace);
      var cmds = [kx(comp, ns) + ' set resources ' + ref + ' -c ' + ctr + ' --limits=' + res + '=' + cut.before + (req ? ' --requests=' + res + '=' + req.before : ''),
        kx(comp, ns) + ' rollout status ' + ref + ' --timeout=5m'];
      var caveats = [
        'Changing resources rolls the pods (a rolling restart).',
        'The next helm upgrade sets the limit back to ' + cut.after + ' unless the chart values change too; until then Helm\'s record and the cluster differ.',
        gitopsCaveat(cut.release, ns, 'revert this kubectl change')
      ];
      var hungry = h.changes.filter(function (c) { return c.componentId === cut.componentId && (c.category === 'env' || c.category === 'configmap') && c.before == null && /cache|warm|buffer|heap|memory|prefetch|batch|preload/i.test(c.field || ''); });
      if (hungry.length) caveats.push('The same release also added ' + hungry.map(function (c) { return envName(c.field) || c.summary; }).slice(0, 2).join(' and ') + '; with ' + (hungry.length > 1 ? 'them' : 'it') + ' still on, memory use may exceed even the old limit.');
      add({
        _key: cut.id, kind: 'resource-restore',
        title: 'Restore ' + (comp ? comp.name : cut.resourceName) + ' ' + res + ' limit to ' + cut.before,
        commands: cmds, risk: 'medium', fixes: [x.id], caveats: caveats,
        prerequisites: ['Nodes have room for ' + cut.before + ' per pod (kubectl describe nodes, Allocated resources).']
      });
    });

    // ---- config-revert ---------------------------------------------------------------------------
    var seenCfg = {};
    hyps.forEach(function (x) {
      if (!/^(dns|config-error|bad-deploy|network-policy|connection-exhaustion)$/.test(x.category)) return;
      primaryChangeIds(x).forEach(function (id) {
        var c = changeById[id];
        if (!c || !/^(configmap|env|secret)$/.test(c.category) || c.risk === 'low' || seenCfg[c.id] || rolledBackChange(c)) return;
        seenCfg[c.id] = true;
        var d = (h.deploys || []).filter(function (dd) { return dd.release && dd.release === c.release; })[0] || null;
        var comp = h.comps[c.componentId] || h.comps[x.componentId];
        var ns = c.namespace || (comp && comp.namespace) || '<namespace>';
        var o = d || comp;
        var cmds = [], caveats = [], prereq = [];
        var restart = comp && comp.type !== 'external' && comp.type !== 'node' ? kx(o, comp.namespace) + ' rollout restart ' + H().workloadRef(comp) : null;
        var title;
        if (c.category === 'configmap') {
          if (d && d.previousRevision != null) {
            cmds.push('helm get manifest ' + d.release + ' --revision ' + d.previousRevision + ' -n ' + (d.namespace || ns) + ' --kube-context ' + ctxName(d) +
              " | yq 'select(.kind == \"ConfigMap\" and .metadata.name == \"" + c.resourceName + "\")' | " + kx(o, ns) + ' apply -f -');
            prereq.push('yq v4 (mikefarah/yq) on your PATH.');
            title = 'Restore ConfigMap ' + c.resourceName + ' from r' + d.previousRevision;
          } else {
            cmds.push(kx(o, ns) + ' edit configmap ' + c.resourceName);
            caveats.push('Set it back by hand: ' + c.summary + ' (restore the left-hand value).');
            title = 'Restore ConfigMap ' + c.resourceName;
          }
          if (restart) cmds.push(restart);
          caveats.push('Pods read ConfigMap values given as environment variables only at start-up, hence the restart; mounted files update after the kubelet sync (often a minute or more).');
          if (comp && comp.name === 'coredns') caveats.push('If the Corefile uses the reload plugin, CoreDNS also picks up the restored file once the kubelet syncs it; the restart applies it at once and clears the crash loop.');
          if (comp && comp.name === 'coredns' && managedDns(comp)) caveats.push(managedDns(comp));
        } else if (c.category === 'env') {
          var ev = envName(c.field) || 'VAR';
          var ref = kindRef(c.resourceKind, c.resourceName);
          var ctr = containerOf(c.field);
          var cflag = ctr ? ' -c ' + ctr : '';
          if (c.before == null) cmds.push(kx(o, ns) + ' set env ' + ref + cflag + ' ' + ev + '-');
          else if (c.before === '(redacted)') cmds.push(kx(o, ns) + ' set env ' + ref + cflag + ' ' + ev + '=<previous-value>');
          else cmds.push(kx(o, ns) + ' set env ' + ref + cflag + ' ' + ev + '=' + (/\s/.test(c.before) ? "'" + c.before + "'" : c.before));
          caveats.push('Changing an environment variable rolls the pods.');
          title = (c.before == null ? 'Remove ' : 'Restore ') + ev + ' on ' + c.resourceName;
        } else {
          var key = /\.(?:data|stringData)\.([\w.-]+)$/.exec(c.field || '');
          cmds.push(kx(o, ns) + ' create secret generic ' + c.resourceName + ' --from-literal=' + (key ? key[1] : '<key>') + '=<previous-value> --dry-run=client -o yaml | ' + kx(o, ns) + ' apply -f -');
          if (restart) cmds.push(restart);
          caveats.push('The old value is not in the paste (secrets are redacted); take it from your secret store. A Secret created this way replaces all its keys — include every key it had.');
          title = 'Restore Secret ' + c.resourceName;
        }
        caveats.push('The next helm upgrade applies the new value again unless the chart values change too.');
        caveats.push(gitopsCaveat(c.release, ns, 'revert this change'));
        add({
          _key: c.id, kind: 'config-revert', title: title, commands: cmds, risk: c.category === 'secret' ? 'medium' : 'low',
          fixes: fixesFor(function (y) { return primaryChangeIds(y).indexOf(c.id) >= 0; }), caveats: caveats, prerequisites: prereq
        });
      });
    });

    // ---- rollout-undo / set-image -----------------------------------------------------------------
    h.deploys.forEach(function (d) {
      var comp = d.componentId ? h.comps[d.componentId] : null;
      if (!comp || comp.type === 'external' || comp.type === 'node') return;
      var rel = h.changes.filter(function (c) { return d.release ? c.release === d.release : c.componentId === comp.id; });
      var meaningful = rel.filter(function (c) { return c.risk !== 'low'; });
      var imageOnly = meaningful.length > 0 && meaningful.every(function (c) { return c.category === 'image'; });
      var fromRollout = d.deployedAtSource === 'rollout-event' && !d.release;
      if ((!imageOnly && !fromRollout) || d.rolledBack) return;
      var ref = H().workloadRef(comp);
      var caveats = ['Reverts only the pod template (image, environment, resources); ConfigMaps, autoscalers and Services stay as they are.'];
      if (d.release) caveats.push('rollout undo leaves Helm release history out of sync (Helm still records r' + d.revision + '); follow with helm rollback or a fix-forward, or the next helm upgrade reapplies the change.');
      caveats.push(gitopsCaveat(d.release, comp.namespace, 'undo this rollback'));
      add({
        _key: comp.id, kind: 'rollout-undo', title: 'Undo the last rollout of ' + comp.name,
        commands: [kx(comp, comp.namespace) + ' rollout undo ' + ref, kx(comp, comp.namespace) + ' rollout status ' + ref + ' --timeout=5m'],
        risk: 'low',
        fixes: fixesFor(function (x) { return x.componentId === comp.id && /^(bad-deploy|image-pull|probe-misconfig|resource-limits|config-error)$/.test(x.category); }),
        caveats: caveats,
        prerequisites: ['The previous ReplicaSet still exists (check: ' + kx(comp, comp.namespace) + ' rollout history ' + ref + ').']
      });
    });
    hyps.forEach(function (x) {
      var imgs = [];
      if (x.category === 'image-pull') {
        var ids = WR.uniq(primaryChangeIds(x).concat(x._imageChanges || []));
        imgs = ids.map(function (id) { return changeById[id]; }).filter(function (c) { return c && c.category === 'image' && c.before && /[:@]/.test(c.before); });
      }
      if (!imgs.length && x.category === 'bad-deploy') {
        var relImgs = h.changes.filter(function (c) { return c.release && c.release === x._release && c.category === 'image' && c.before && /[:@]/.test(c.before); });
        var relMeaningful = h.changes.filter(function (c) { return c.release && c.release === x._release && c.risk !== 'low'; });
        if (relImgs.length && relMeaningful.every(function (c) { return c.category === 'image'; })) imgs = [relImgs[0]];
      }
      imgs.forEach(function (img) { pinImage(x, img); });
      // A tag that differs from the chart's app version only by a "v": fix it forward instead.
      if (x._tagFix && imgs.length) tagFixForward(x, imgs);
    });
    function tagFixForward(x, imgs) {
      var d = h.deploys.filter(function (dd) { return dd.release && dd.release === imgs[0].release; })[0];
      if (!d) return;
      var good = imgs.map(function (c) { return c.after.replace(/:[^:@\/]+$/, ':' + x._tagFix.app); });
      var valuesKey = h.changes.filter(function (c) { return c.release === d.release && c.category === 'image' && !/containers\[/.test(c.field || '') && /(^|\.)tag$/.test(c.field || ''); })[0];
      var ns = d.namespace || '<namespace>';
      add({
        _key: 'tagfix|' + d.release, kind: 'roll-forward', title: 'Fix the image tag to ' + x._tagFix.app + ' and upgrade ' + d.release,
        commands: good.map(function (ref) { return 'docker manifest inspect ' + ref; }).concat([
          'helm upgrade ' + d.release + ' <chart> --version ' + (d.chartTo ? String(d.chartTo).replace(/^.*?-(\d[\w.+-]*)$/, '$1') : '<chart-version>') + ' -n ' + ns + ' --kube-context ' + ctxName(d) +
            ' --reuse-values --set ' + (valuesKey ? valuesKey.field : 'image.tag') + '=' + x._tagFix.app + ' --wait --timeout 5m'
        ]),
        risk: 'medium', etaMinutes: 10, fixes: [x.id],
        caveats: ['Run the upgrade only if every docker manifest inspect above succeeds; otherwise the tag is missing for another reason.',
          'This also ships the rest of r' + (d.revision != null ? d.revision : 'the release') + ' (its other changes are listed on the Helm rollback option).',
          gitopsCaveat(d.release, ns, 'put the old tag back')].concat(valuesKey ? [] : ['The values key for the tag is a guess (image.tag); use the key your chart reads.']),
        prerequisites: ['Replace <chart> with the chart reference you deploy from.']
      });
    }
    function pinImage(x, img) {
      if (!img || rolledBackChange(img)) return;
      var comp = h.comps[img.componentId] || h.comps[x.componentId];
      var ctr = containerOf(img.field) || (comp ? comp.name : img.resourceName);
      var ref = kindRef(img.resourceKind, img.resourceName);
      add({
        _key: img.id, kind: 'set-image', title: 'Pin ' + img.resourceName + ' to its previous image',
        commands: [kx(comp, img.namespace || comp.namespace) + ' set image ' + ref + ' ' + ctr + '=' + img.before, kx(comp, img.namespace || comp.namespace) + ' rollout status ' + ref + ' --timeout=5m'],
        risk: 'low', fixes: fixesFor(function (y) { return y.id === x.id || primaryChangeIds(y).indexOf(img.id) >= 0; }),
        caveats: ['The next helm upgrade sets the new image again unless the chart values change too.', 'Only the image changes; other settings from the release stay.',
          gitopsCaveat(img.release, img.namespace || comp.namespace, 'revert this kubectl change')],
        prerequisites: ['The old image ' + img.before + ' is still in the registry.']
      });
    }

    // ---- scale: undo a replica / autoscaler increase behind connection exhaustion -------------------
    hyps.forEach(function (x) {
      if (x.category !== 'connection-exhaustion' || !x._demandChange) return;
      var c = x._demandChange;
      if (c.before == null || isNaN(Number(c.before)) || rolledBackChange(c)) return;
      var comps = [x.componentId].concat(x.relatedComponentIds || []).map(function (id) { return h.comps[id]; }).filter(Boolean);
      var cmds = [], caveats = [];
      comps.forEach(function (comp) {
        var ns = comp.namespace;
        if (c.category === 'hpa') cmds.push(kx(comp, ns) + ' patch hpa ' + c.resourceName + ' --type merge -p \'{"spec":{"maxReplicas":' + Number(c.before) + '}}\'');
        else if (c.category === 'replicas') cmds.push(kx(comp, ns) + ' scale ' + kindRef(c.resourceKind, c.resourceName) + ' --replicas=' + Number(c.before));
      });
      if (!cmds.length) return;
      var what = c.category === 'hpa' ? 'maxReplicas' : 'replicas';
      caveats.push('The next helm upgrade sets ' + what + ' back to ' + c.after + ' unless the chart values change too.');
      caveats.push('Pods above the new limit are stopped; requests in flight on them can fail, and peak traffic may need more than ' + c.before + ' pods.');
      caveats.push('Database connections fall only as pods stop; watch the connection count (pg_stat_activity) drop below the limit.');
      if (comps.length > 1) caveats.push('The command for ' + comps.slice(1).map(function (cc) { return cc.cluster; }).join(', ') + ' assumes it runs the same chart values (' + what + ' ' + c.before + ' before the change).');
      caveats.push(gitopsCaveat(c.release, comps[0].namespace, 'revert this patch'));
      // Every pool that lands on the same database counts against one limit.
      var scaledNames = comps.map(function (cc) { return cc.name; });
      var otherPools = WR.uniq(h.compList.filter(function (cc) {
        return cc.type === 'service' && scaledNames.indexOf(cc.name) < 0 && cc._kindCount && (cc._kindCount.conn_exhaustion || cc._kindCount.db_error);
      }).map(function (cc) { return cc.name; }));
      var scaledClusters = WR.uniq(comps.map(function (cc) { return cc.cluster; }));
      var nClusters = scaledClusters.length > 1 && sharedStores(scaledClusters).length ? scaledClusters.length : 1;
      add({
        _key: c.id, kind: 'scale', title: 'Lower ' + c.resourceName + ' ' + what + ' back to ' + c.before,
        commands: cmds, risk: 'low', fixes: [x.id], caveats: caveats,
        prerequisites: ['Confirm ' + what + ' ' + c.before + ' × the pool size per pod' + (nClusters > 1 ? ' × ' + nClusters + ' clusters sharing the database' : '') +
          (otherPools.length ? ', plus the ' + otherPools.join(' and ') + ' pools,' : '') + ' stays under the database limit (SHOW max_connections).']
      });
    });

    // ---- canary-abort: Argo Rollouts --------------------------------------------------------------
    var rolloutObjs = h.changes.filter(function (c) { return c.resourceKind === 'Rollout'; });
    WR.uniq(rolloutObjs.map(function (c) { return c.resourceName + '|' + c.namespace; })).forEach(function (k) {
      var c = rolloutObjs.filter(function (x) { return x.resourceName + '|' + x.namespace === k; })[0];
      if (rolledBackChange(c)) return;
      var comp = h.comps[c.componentId] || null;
      var o = comp || { cluster: null, clusterKnown: false };
      var flags = ' -n ' + (c.namespace || '<namespace>') + ' --context ' + ctxName(o);
      add({
        _key: k, kind: 'canary-abort', title: 'Abort the canary of ' + c.resourceName,
        commands: ['kubectl argo rollouts abort ' + c.resourceName + flags, 'kubectl argo rollouts status ' + c.resourceName + flags],
        risk: 'low', etaMinutes: 2,
        fixes: fixesFor(function (x) { return (comp && x.componentId === comp.id) || (c.release && x._release === c.release); }),
        caveats: ['Abort sends traffic back to the stable ReplicaSet; the Rollout stays Degraded until you retry it or revert its spec (kubectl argo rollouts undo).']
          .concat(h.changes.some(function (x) { return x.category === 'migration-hook' && x.release && x.release === c.release; })
            ? ['The release\'s pre-upgrade migration already ran; the stable version must work with the new database schema.'] : []),
        prerequisites: ['The Argo Rollouts kubectl plugin is installed.']
      });
    });

    // ---- traffic-shift: only some clusters failing ------------------------------------------------
    if (h.clusters.length >= 2 && failingClusters.length && healthyClusters.length) {
      var f0 = failingClusters[0];
      add({
        _key: failingClusters.join(','), kind: 'traffic-shift',
        title: 'Shift user traffic away from ' + failingClusters.join(' and ') + ' to ' + healthyClusters.join(' and '),
        commands: [
          'aws route53 change-resource-record-sets --hosted-zone-id <zone-id> --change-batch file://<weight-0-for-' + f0 + '>.json',
          'az network traffic-manager endpoint update --resource-group <resource-group> --profile-name <profile> --type azureEndpoints --name <' + f0 + '-endpoint> --endpoint-status Disabled',
          'kubectl --context <gateway-cluster> -n <namespace> patch httproute <route> --type=json -p \'[{"op":"replace","path":"/spec/rules/0/backendRefs/<index-of-' + f0 + '>/weight","value":0}]\''
        ],
        risk: 'medium',
        fixes: fixesFor(function (x) { var c = h.comps[x.componentId]; return !!c && failingClusters.indexOf(c.cluster) >= 0; }),
        caveats: [
          'These are templates for three common layers (DNS weights, a cloud traffic manager, a Gateway API route); use the one that routes users between your clusters and fill the <…> placeholders.',
          healthyClusters.join(' and ') + ' must absorb the extra load; check autoscaler maximums and node capacity first.',
          'A DNS-based shift takes effect only as resolver caches expire (the record\'s TTL).',
          'This does not fix ' + failingClusters.join(' and ') + '; roll back or fix it before shifting traffic back, and do not roll the suspect release out to the healthy cluster meanwhile.'
        ],
        prerequisites: ['Know which layer sends users to each cluster, and that ' + healthyClusters.join(' and ') + (healthyClusters.length > 1 ? ' serve' : ' serves') + ' the same routes.']
      });
    }

    // ---- roll-forward -----------------------------------------------------------------------------
    hyps.forEach(function (x) {
      var comp = h.comps[x.componentId];
      if (!comp) return;
      if (x.category === 'tls-cert') {
        var cert = x._cert || {};
        var name = cert.name || comp.name + '-tls';
        var ns = cert.namespace || comp.namespace;
        var o = { cluster: cert.cluster || comp.cluster, clusterKnown: cert.cluster ? true : comp.clusterKnown };
        var caveats = [], prereq = ['cmctl (the cert-manager command-line tool) is installed.'];
        var eta = 15;
        if (cert.issuerError) {
          caveats.push('cert-manager has failed to renew this certificate' + (cert.failedAttempts ? ' ' + cert.failedAttempts + ' times' : '') + ': ' + quote(cert.issuerError.text, 140) + '. Fix the issuer first (for a Vault issuer, the role or policy it signs with), or the renewal fails again.');
          prereq.push('The issuer' + (cert.issuer ? ' ' + cert.issuer : '') + ' can sign again.');
          eta = 30;
        }
        if (!cert.name) caveats.unshift('No cert-manager output was pasted, so the Certificate name ' + name + ' is a guess; list the real ones first: ' + kx(o, ns) + ' get certificate');
        caveats.push('Workloads that load the certificate only at start-up need the restart; mounted Secrets update after the kubelet sync (often a minute or more).');
        if (h.deploys.some(function (d) { return d.release && d.previousRevision != null; })) caveats.push('Rolling back a Helm release does not help: none of the pasted Helm changes touched this certificate.');
        add({
          _key: name + '|' + ns, kind: 'roll-forward', title: 'Renew certificate ' + name + ' and restart ' + comp.name,
          commands: [
            'cmctl renew ' + name + ' -n ' + ns + ' --context ' + ctxName(o),
            kx(o, ns) + ' wait certificate/' + name + ' --for=condition=Ready --timeout=5m',
            kx(comp, comp.namespace) + ' rollout restart ' + H().workloadRef(comp)
          ],
          risk: 'medium', etaMinutes: eta, fixes: [x.id], caveats: caveats, prerequisites: prereq
        });
      } else if (x.category === 'bad-deploy' && /^migration-hook/.test(x.rule)) {
        // The pre-upgrade migration already changed the database, so rolling the code back is not
        // safe by default; a fixed release that works with the new schema is.
        var d = h.deploys.filter(function (dd) { return dd.release === x._release; })[0];
        if (!d) return;
        add({
          _key: 'mig|' + d.release, kind: 'roll-forward', title: 'Fix forward release ' + d.release + ' (the migration already ran)',
          commands: ['helm upgrade ' + d.release + ' <chart> --version <fixed-chart-version> -n ' + (d.namespace || '<namespace>') + ' --kube-context ' + ctxName(d) + ' --reuse-values --wait --timeout 5m'],
          risk: 'medium', etaMinutes: 30, fixes: [x.id],
          caveats: ['A rollback would leave the database at the new schema with the old code; a fixed release keeps them in step.',
            '--reuse-values keeps the values of the current release; pass -f with your values file instead if the fix is in the values.'],
          prerequisites: ['A chart version with the fix is published (replace the <…> placeholders).']
        });
      } else if (x.category === 'dns' && !citedChangeIds(x).length && comp.name === 'coredns') {
        add({
          _key: 'dns|' + comp.id, kind: 'roll-forward', title: 'Fix the CoreDNS configuration in ' + comp.cluster,
          commands: [kx(comp, 'kube-system') + ' edit configmap coredns', kx(comp, 'kube-system') + ' rollout restart deployment/coredns'],
          risk: 'medium', etaMinutes: 15, fixes: [x.id],
          caveats: ['No pasted change explains the failure, so check the forward targets and upstream resolvers before editing.'].concat(managedDns(comp) ? [managedDns(comp)] : []),
          prerequisites: ['A known-good Corefile to compare with.']
        });
      }
    });

    // ---- roll-forward for causes no revert can fix: a missing ConfigMap/Secret, a sick node --------
    hyps.forEach(function (x) {
      var comp = h.comps[x.componentId];
      if (!comp) return;
      if (x.category === 'config-error' && !primaryChangeIds(x).length) {
        var sigs = (h.sigsByComp[comp.id] || []).filter(function (s) { return s.kind === 'config_error'; });
        var miss = null;
        sigs.some(function (s) { var m = /(secret|configmap)s? "([^"]+)" not found/i.exec(s.text || ''); if (m) miss = { kind: m[1].toLowerCase(), name: m[2] }; return !!m; });
        if (!miss) return;
        add({
          _key: 'missing|' + miss.kind + '|' + miss.name, kind: 'roll-forward', title: 'Create the missing ' + (miss.kind === 'secret' ? 'Secret' : 'ConfigMap') + ' ' + miss.name,
          commands: [kx(comp, comp.namespace) + ' create ' + (miss.kind === 'secret' ? 'secret generic ' : 'configmap ') + miss.name + ' --from-literal=<key>=<value>',
            kx(comp, comp.namespace) + ' get pods -w'],
          risk: 'low', etaMinutes: 5, fixes: [x.id],
          caveats: ['Use the keys the pod spec references (see describe pod); the kubelet retries waiting containers on its own once the object exists.',
            'If the object was created by Helm before, find out why it is gone before recreating it by hand.'],
          prerequisites: ['The real value' + (miss.kind === 'secret' ? ', from your secret store' : '') + '.']
        });
      } else if (x.category === 'node-pressure' && comp.type === 'node') {
        add({
          _key: 'node|' + comp.id, kind: 'roll-forward', title: 'Take node ' + comp.name + ' out of service',
          commands: [kx(comp) + ' cordon ' + comp.name, kx(comp) + ' drain ' + comp.name + ' --ignore-daemonsets --delete-emptydir-data --timeout=10m'],
          risk: 'medium', etaMinutes: 12, fixes: [x.id],
          caveats: ['Draining evicts every pod on the node; workloads without spare replicas or with a strict PodDisruptionBudget pause the drain.',
            'emptyDir data on the node is lost.', 'The cluster autoscaler (if any) replaces the capacity; otherwise the other nodes must have room.'],
          prerequisites: ['The remaining nodes can hold the moved pods (kubectl top node).']
        });
      }
    });

    // ---- restart: stop-gap -----------------------------------------------------------------------
    if (top) {
      var tc = h.comps[top.componentId];
      // A restart only buys time when no change is the cause: it cannot undo a bad Corefile, a
      // lowered limit or a higher replica ceiling, so it is offered only for these cases.
      var changeDriven = primaryChangeIds(top).length > 0;
      var restartHelps = top.category === 'dependency-failure' || top.category === 'unknown' ||
        ((top.category === 'dns' || top.category === 'connection-exhaustion') && !changeDriven);
      if (tc && (tc.type === 'service' || tc.type === 'infra') && restartHelps) {
        var rc = ['Stop-gap only: the cause stays, and the failures are likely to come back.'];
        if (top.category === 'connection-exhaustion') rc.push('All pods reconnect at once after a restart and can hit the connection limit again.');
        if (top.category === 'dns') rc.push('Restarting CoreDNS with the same configuration does not fix lookups that fail upstream.');
        add({
          _key: tc.id, kind: 'restart', title: 'Restart ' + tc.name + ' (stop-gap)',
          commands: [kx(tc, tc.namespace) + ' rollout restart ' + H().workloadRef(tc), kx(tc, tc.namespace) + ' rollout status ' + H().workloadRef(tc) + ' --timeout=5m'],
          risk: 'low', fixes: [top.id], caveats: rc, prerequisites: [], _effect: 0.3
        });
      }
    }

    // ---- scale: lower the connection demand when no change explains it --------------------------
    // Ahead of a restart in the preference order: restarted pods reconnect at once into the same limit.
    if (top && top.category === 'connection-exhaustion' && !out.some(function (r) { return r.kind === 'scale' && r.fixes.indexOf(top.id) >= 0; })) demandCut(top);

    // ---- fallback: a root suspect always gets an option, or an explicit "none applies" -----------
    if (top && top.confidence >= 0.35 && !out.some(function (r) { return r.fixes.indexOf(top.id) >= 0; })) fallback(top);

    function demandCut(x) {
      var tc = h.comps[x.componentId];
      if (!tc) return;
      var rb = Object.keys(rolledBackRel).map(function (k) { return rolledBackRel[k]; })
        .filter(function (d) { return d.componentId === tc.id || (tc.release && d.release === tc.release); })[0] || null;
      // Too many clients for the database: lower the demand from the callers. A database restart
      // would drop every connection, healthy ones included, and the clients would reconnect at
      // once into the same limit.
      var clients = clientsOf(tc);
      var cmds = clients.map(function (c) {
        var hpa = hpaNameFor(c);
        return hpa ? kx(c, c.namespace) + ' patch hpa ' + hpa + ' --type merge -p \'{"spec":{"maxReplicas":<lower-max>}}\''
          : kx(c, c.namespace) + ' scale ' + H().workloadRef(c) + ' --replicas=<fewer-replicas>';
      });
      if (!cmds.length) cmds.push('kubectl --context <kube-context> -n <namespace> scale deployment/<client> --replicas=<fewer-replicas>');
      add({
        _key: 'demand|' + tc.id, kind: 'scale',
        title: 'Lower the connection demand on ' + (tc.type === 'datastore' ? tc.name : 'the database') + (clients.length ? ' from ' + WR.uniq(clients.map(function (c) { return c.name; })).join(', ') : ''),
        commands: cmds, risk: 'medium', fixes: [x.id],
        caveats: ['Replace the <…> placeholder with a count where count × connection-pool size per pod stays under the database limit (SHOW max_connections).',
          'Stop-gap: no pasted change explains the demand; find what raised it (more replicas, a bigger pool, slow queries holding connections).',
          'Pods above the new count are stopped; requests in flight on them can fail.'].concat(rb ? ['Release ' + rb.release + ' was already rolled back to r' + rb.rolledBack.to + ' at ' + WR.time.fmt(rb.rolledBack.at) + ' UTC.'] : []),
        prerequisites: ['Know the pool size per pod (for example HikariCP maximumPoolSize, pgx pool_max_conns).']
      });
    }

    function fallback(x) {
      var tc = h.comps[x.componentId];
      if (!tc) return;
      var rb = Object.keys(rolledBackRel).map(function (k) { return rolledBackRel[k]; })
        .filter(function (d) { return d.componentId === tc.id || (tc.release && d.release === tc.release); })[0] || null;
      var rbNote = rb ? 'Release ' + rb.release + ' was already rolled back to r' + rb.rolledBack.to + ' at ' + WR.time.fmt(rb.rolledBack.at) + ' UTC; failures that continue after that point to more than the release.' : null;

      if (x.category === 'connection-exhaustion') { demandCut(x); return; }
      // A restart buys time only when the process itself is wedged or bloated (stale connections to
      // a dependency, memory growth, an unknown fault). It does nothing for a provider's rate limit,
      // a missing image or config, no room to schedule, a blocking policy or a bad certificate.
      if ((tc.type === 'service' || tc.type === 'infra') && /^(unknown|dependency-failure|resource-limits)$/.test(x.category)) {
        var cav = ['Stop-gap only: a restart does not remove the cause, and the failures are likely to come back.'];
        var cited = primaryChangeIds(x).map(function (id) { return changeById[id]; }).filter(Boolean);
        if (cited.length && !rb) cav.push('It does not undo ' + cited[0].summary + '; revert that change for a real fix.');
        if (rbNote) cav.push(rbNote);
        if (x.category === 'resource-limits') cav.push('Pods restart into the same memory limit; raise it if they are still killed.');
        add({
          _key: 'fallback|' + tc.id, kind: 'restart', title: 'Restart ' + tc.name + ' (stop-gap)',
          commands: [kx(tc, tc.namespace) + ' rollout restart ' + H().workloadRef(tc), kx(tc, tc.namespace) + ' rollout status ' + H().workloadRef(tc) + ' --timeout=5m'],
          risk: 'low', fixes: [x.id], caveats: cav, prerequisites: [], _effect: 0.3
        });
        return;
      }
      // Nothing to roll back and no restart that helps (a datastore or external dependency, a rate
      // limit, a capacity shortage): say so instead of inventing an option.
      if (h.warn) h.warn('No rollback or stop-gap applies to ' + tc.name + ' (' + x.category.replace(/-/g, ' ') + ') from the pasted evidence; use the next checks under the top root cause.');
    }

    // Workloads that call a component: trace/log edges into it, else failing services in the same
    // cluster that show the client side of the problem.
    function clientsOf(tc) {
      var ids = [tc.id].concat(top && top.componentId === tc.id ? (top.relatedComponentIds || []) : []);
      var out2 = [];
      ids.forEach(function (id) {
        var c = h.comps[id];
        if (!c) return;
        if (c.type === 'service') { out2.push(c); return; }
        var callers = (h.edgesTo[id] || []).map(function (e) { return h.comps[e.from]; }).filter(function (x) { return x && x.type === 'service' && x.status !== 'healthy'; });
        if (!callers.length) {
          callers = h.compList.filter(function (x) {
            return x.type === 'service' && x.cluster === c.cluster && x.status !== 'healthy' && x.role !== 'ingress' &&
              x._kindCount && (x._kindCount.conn_exhaustion || x._kindCount.db_error || x._kindCount.hpa_maxed);
          });
        }
        callers.forEach(function (x) { out2.push(x); });
      });
      // Same-named clients in other failing clusters show the same pattern.
      h.compList.forEach(function (x) {
        if (x.type === 'service' && x.status !== 'healthy' && out2.some(function (c) { return c.name === x.name && c.id !== x.id; }) && out2.indexOf(x) < 0 &&
            x._kindCount && (x._kindCount.conn_exhaustion || x._kindCount.db_error || x._kindCount.hpa_maxed)) out2.push(x);
      });
      return WR.uniq(out2, function (c) { return c.id; });
    }
    function hpaNameFor(c) {
      var s = (h.sigsByComp[c.id] || []).filter(function (x) { return x.kind === 'hpa_maxed'; })[0];
      if (!s) return null;
      var L = s.attrs && s.attrs.labels;
      return (s.attrs && s.attrs.hpa) || (L && L.horizontalpodautoscaler) || c.name;
    }

    // ---- recommendation and budget saved ------------------------------------------------------------
    function pref(r) { var i = PREFERENCE.indexOf(r.kind); return (i < 0 ? 50 : i) + (r.risk === 'high' ? 8 : 0); }
    var fixingTop = top ? out.filter(function (r) { return r.fixes.indexOf(top.id) >= 0; }) : [];
    var pool = fixingTop.length ? fixingTop : out;
    var best = pool.slice().sort(function (a, b) {
      return pref(a) - pref(b) || RISK_RANK[a.risk] - RISK_RANK[b.risk] || a.etaMinutes - b.etaMinutes || (a.id < b.id ? -1 : 1);
    })[0] || null;
    out.forEach(function (r) {
      r.recommended = r === best;
      var addressesTop = top && r.fixes.indexOf(top.id) >= 0;
      r.budgetSavedPct = addressesTop && h.budget ? WR.budget.savedPct(h.budget, r.etaMinutes, r._effect != null ? r._effect : 1) : null;
    });
    out.sort(function (a, b) { return (b.recommended ? 1 : 0) - (a.recommended ? 1 : 0) || a.etaMinutes - b.etaMinutes || pref(a) - pref(b); });
    return out.map(function (r) {
      return {
        id: r.id, title: r.title, kind: r.kind, commands: r.commands, etaMinutes: r.etaMinutes, risk: r.risk,
        recommended: r.recommended, fixes: r.fixes, caveats: r.caveats, prerequisites: r.prerequisites, budgetSavedPct: r.budgetSavedPct
      };
    });
  }

  rollbacks.PREFERENCE = PREFERENCE;
  WR.rollbacks = rollbacks;
})(globalThis.WR = globalThis.WR || {});
