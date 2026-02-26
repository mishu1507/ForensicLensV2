from flask import (
    Flask, render_template, request,
    redirect, url_for, session,
    make_response, jsonify
)
import os
import uuid
import json

from modules.workspace_manager import create_workspace, cleanup_workspace
from modules.parser import parse_logs
from modules.auth_detector import detect_attacks
from modules.incident_analyzer import classify_incident
from modules.risk_engine import calculate_risk, calculate_entity_risk_timeline
from modules.timeline import build_timeline
from modules.narrative_generator import generate_narrative, generate_attack_storyline
from modules.report_generator import generate_report
from modules.hash_integrity import calculate_hashes
from modules.mitre_mapper import (
    map_mitre, get_mitre_heatmap_data, detect_attack_chains,
    get_coverage_score, TACTICS, TECHNIQUES
)
from modules.correlation_engine import (
    run_all_detections, build_entity_graph, build_process_tree
)
from modules.query_engine import execute_query
from modules.entity_engine import EntityEngine, build_entity_data
from modules.ai_hunter import (
    translate_nl_query, generate_investigation_summary,
    generate_detection_suggestions
)
from modules.highlight_engine import get_highlight_rules_json
from modules.attack_chain_engine import AttackChainEngine
from modules.rule_builder import RuleEngine, DEFAULT_RULES
from modules.ioc_enrichment import IOCEngine
from modules.case_manager import CaseManager
from modules.playbook_engine import PlaybookEngine

app = Flask(__name__)
app.secret_key = "forensiclens-secret-key"
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max


# ──────────────────────────────────────────────
# In-memory data store for active cases
# ──────────────────────────────────────────────
case_store = {}
case_mgr = CaseManager()
rule_engines = {}  # per-case rule engines


# ──────────────────────────────────────────────
# ORIGINAL ROUTES (preserved)
# ──────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    workspace = create_workspace()
    case_id = str(uuid.uuid4())

    uploaded_files = request.files.getlist("logfiles")
    log_paths = []

    for f in uploaded_files:
        path = os.path.join(workspace, f.filename)
        f.save(path)
        log_paths.append(path)

    # Enhanced parsing pipeline
    events = parse_logs(log_paths)
    mitre_techniques = map_mitre(events)
    attacks = detect_attacks(events)
    incident_type = classify_incident(events, attacks)
    risk_score, severity = calculate_risk(events, attacks)
    timeline = build_timeline(events)
    narrative = generate_narrative(timeline, incident_type, severity, attacks)
    file_hashes = calculate_hashes(log_paths)

    # Advanced analysis
    detections = run_all_detections(events)
    heatmap_data = get_mitre_heatmap_data(events)
    attack_chains = detect_attack_chains(events)
    coverage = get_coverage_score(events)
    entity_graph = build_entity_graph(events)
    process_tree = build_process_tree(events)
    entity_summary = build_entity_data(events)
    highlight_rules = get_highlight_rules_json()

    # AI analysis
    ai_summary = generate_investigation_summary(
        events, detections, mitre_techniques, entity_summary
    )
    detection_suggestions = generate_detection_suggestions(events, detections)

    # Attack chain engine
    ace = AttackChainEngine(events)
    discovered_chains = ace.discover_chains()
    entity_risk_scores = ace.get_entity_risk_scores()
    attack_storyline = ace.generate_storyline()
    attack_graph = ace.build_attack_graph()
    anomalies = ace.detect_anomalies()

    # IOC enrichment
    ioc_engine = IOCEngine()
    ioc_matches = ioc_engine.scan_events(events)
    ioc_summary = ioc_engine.get_enrichment_summary(events)

    # Rule engine
    re_ = RuleEngine()
    for rule in DEFAULT_RULES:
        re_.add_rule(rule)
    rule_results = re_.evaluate_all(events)
    rule_engines[case_id] = re_

    # Entity risk timeline
    entity_risk_timeline = calculate_entity_risk_timeline(events)

    # Attack storyline
    storyline_chapters = generate_attack_storyline(events, attack_chains, mitre_techniques)

    # Case management
    case_mgr.create_case(case_id, description=f"Case {case_id[:8]} – {incident_type}")

    # Playbook generation
    pb_engine = PlaybookEngine()
    playbook = pb_engine.get_playbook(incident_type, events)

    # Threat pulses for the global ticker
    threat_pulses = generate_threat_pulses(detections, anomalies, ioc_matches, attack_chains, severity)

    # Store in memory for API access
    case_store[case_id] = {
        "workspace": workspace,
        "events": events,
        "incident_type": incident_type,
        "risk_score": risk_score,
        "severity": severity,
        "timeline": timeline,
        "narrative": narrative,
        "file_hashes": file_hashes,
        "attacks": attacks,
        "mitre_techniques": mitre_techniques,
        "detections": detections,
        "heatmap_data": heatmap_data,
        "attack_chains": attack_chains,
        "coverage": coverage,
        "entity_graph": entity_graph,
        "process_tree": process_tree,
        "entity_summary": entity_summary,
        "highlight_rules": highlight_rules,
        "ai_summary": ai_summary,
        "detection_suggestions": detection_suggestions,
        "discovered_chains": discovered_chains,
        "entity_risk_scores": entity_risk_scores,
        "attack_storyline": attack_storyline,
        "attack_graph": attack_graph,
        "anomalies": anomalies,
        "ioc_matches": ioc_matches,
        "ioc_summary": ioc_summary,
        "rule_results": rule_results,
        "entity_risk_timeline": entity_risk_timeline,
        "storyline_chapters": storyline_chapters,
        "playbook": playbook,
        "threat_pulses": threat_pulses,
    }

    # Store minimal session reference (avoid cookie overflow)
    session[case_id] = {"workspace": workspace}

    session["current_case"] = case_id
    return redirect(url_for("chain_of_custody"))


@app.route("/chain-of-custody", methods=["GET", "POST"])
def chain_of_custody():
    if request.method == "POST":
        session["investigator_name"] = request.form["investigator_name"]
        session["investigator_id"] = request.form["investigator_id"]
        session["organization"] = request.form["organization"]

        case_id = session.get("current_case")
        return redirect(url_for("siem", case_id=case_id))

    return render_template("chain_of_custody.html")




@app.route("/download/<case_id>")
def download(case_id):
    data = case_store.get(case_id)
    sess = session.get(case_id, {})
    if not data:
        return "Session expired", 404

    report_path = generate_report(
        data.get("workspace") or sess.get("workspace", ""),
        case_id,
        session.get("investigator_name", "Unknown"),
        session.get("investigator_id", "N/A"),
        session.get("organization", "N/A"),
        data["file_hashes"],
        data["incident_type"],
        data["attacks"],
        data["timeline"],
        data["risk_score"],
        data["severity"],
        data["narrative"]
    )

    with open(report_path, "rb") as f:
        pdf_bytes = f.read()

    cleanup_workspace(data.get("workspace") or sess.get("workspace", ""))
    session.pop(case_id, None)

    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="Forensic_Report_{case_id}.pdf"'
    )
    return response


# ──────────────────────────────────────────────
# SIEM Workspace
# ──────────────────────────────────────────────
@app.route("/siem/<case_id>")
def siem(case_id):
    """Advanced SIEM Workspace."""
    data = case_store.get(case_id)
    if not data:
        return redirect(url_for("index"))

    return render_template(
        "siem.html",
        case_id=case_id,
        data=data,
    )


@app.route("/dashboard/<case_id>")
def dashboard(case_id):
    """Classic Dashboard View."""
    data = case_store.get(case_id)
    if not data:
        return redirect(url_for("index"))

    return render_template(
        "dashboard.html",
        case_id=case_id,
        data=data,
    )


# ──────────────────────────────────────────────
# REST API: Query Engine
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/search", methods=["POST"])
def api_search(case_id):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    body = request.get_json(silent=True) or {}
    query = body.get("query", "")

    result = execute_query(data["events"], query)

    # Limit event data sent to frontend
    events_limited = []
    for e in result["events"][:500]:
        events_limited.append({
            "timestamp": e.get("timestamp"),
            "type": e.get("type"),
            "severity": e.get("severity"),
            "category": e.get("category"),
            "raw": e.get("raw"),
            "user": e.get("user"),
            "ip": e.get("ip"),
            "dest_ip": e.get("dest_ip"),
            "process": e.get("process"),
            "hostname": e.get("hostname"),
            "commandline": e.get("commandline"),
            "source_file": e.get("source_file"),
            "source_type": e.get("source_type"),
            "mitre_techniques": e.get("mitre_techniques", []),
            "mitre_tactics": e.get("mitre_tactics", []),
        })

    return jsonify({
        "total": result["total"],
        "showing": len(events_limited),
        "events": events_limited,
        "aggregation": result["aggregation"],
    })


# ──────────────────────────────────────────────
# REST API: Entity Pivot
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/pivot", methods=["POST"])
def api_pivot(case_id):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    body = request.get_json(silent=True) or {}
    entity_type = body.get("entity_type", "")
    entity_value = body.get("entity_value", "")

    engine = EntityEngine(data["events"])
    result = engine.pivot(entity_type, entity_value)

    # Limit events
    events_limited = []
    for e in result["events"][:200]:
        events_limited.append({
            "timestamp": e.get("timestamp"),
            "type": e.get("type"),
            "severity": e.get("severity"),
            "raw": e.get("raw"),
            "user": e.get("user"),
            "ip": e.get("ip"),
            "process": e.get("process"),
            "hostname": e.get("hostname"),
        })

    return jsonify({
        "entity_type": result["entity_type"],
        "entity_value": result["entity_value"],
        "event_count": result["event_count"],
        "events": events_limited,
        "related_entities": result["related_entities"],
    })


# ──────────────────────────────────────────────
# REST API: AI Natural Language Query
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/ai-query", methods=["POST"])
def api_ai_query(case_id):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    body = request.get_json(silent=True) or {}
    nl_query = body.get("query", "")

    # Translate NL to DSL
    translated, confidence, explanation = translate_nl_query(nl_query)

    # Execute the translated query
    result = execute_query(data["events"], translated)

    events_limited = []
    for e in result["events"][:200]:
        events_limited.append({
            "timestamp": e.get("timestamp"),
            "type": e.get("type"),
            "severity": e.get("severity"),
            "raw": e.get("raw"),
            "user": e.get("user"),
            "ip": e.get("ip"),
            "process": e.get("process"),
        })

    return jsonify({
        "original_query": nl_query,
        "translated_query": translated,
        "confidence": confidence,
        "explanation": explanation,
        "total": result["total"],
        "events": events_limited,
    })


# ──────────────────────────────────────────────
# REST API: Filter events
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/filter", methods=["POST"])
def api_filter(case_id):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    body = request.get_json(silent=True) or {}
    filters = body.get("filters", {})

    events = data["events"]

    # Apply filters
    if filters.get("severity"):
        events = [e for e in events if e.get("severity") == filters["severity"]]
    if filters.get("type"):
        events = [e for e in events if e.get("type") == filters["type"]]
    if filters.get("category"):
        events = [e for e in events if e.get("category") == filters["category"]]
    if filters.get("user"):
        events = [e for e in events
                  if filters["user"].lower() in (e.get("user") or "").lower()]
    if filters.get("ip"):
        events = [e for e in events
                  if filters["ip"] in (e.get("ip") or "")]
    if filters.get("process"):
        events = [e for e in events
                  if filters["process"].lower() in (e.get("process") or "").lower()]
    if filters.get("hostname"):
        events = [e for e in events
                  if filters["hostname"].lower() in (e.get("hostname") or "").lower()]
    if filters.get("mitre_technique"):
        tech_id = filters["mitre_technique"].upper()
        events = [e for e in events
                  if any(tech_id in t.get("id", "") for t in e.get("mitre_techniques", []))]
    if filters.get("mitre_tactic"):
        tac_id = filters["mitre_tactic"].upper()
        events = [e for e in events
                  if any(tac_id in t.get("id", "") for t in e.get("mitre_tactics", []))]
    if filters.get("source_type"):
        events = [e for e in events if e.get("source_type") == filters["source_type"]]

    events_limited = []
    for e in events[:500]:
        events_limited.append({
            "timestamp": e.get("timestamp"),
            "type": e.get("type"),
            "severity": e.get("severity"),
            "category": e.get("category"),
            "raw": e.get("raw"),
            "user": e.get("user"),
            "ip": e.get("ip"),
            "dest_ip": e.get("dest_ip"),
            "process": e.get("process"),
            "hostname": e.get("hostname"),
            "commandline": e.get("commandline"),
            "source_file": e.get("source_file"),
            "source_type": e.get("source_type"),
            "mitre_techniques": e.get("mitre_techniques", []),
            "mitre_tactics": e.get("mitre_tactics", []),
        })

    return jsonify({
        "total": len(events),
        "showing": len(events_limited),
        "events": events_limited,
    })


# ──────────────────────────────────────────────
# REST API: MITRE heatmap data
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/mitre", methods=["GET"])
def api_mitre(case_id):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    return jsonify({
        "heatmap": data.get("heatmap_data", {}),
        "techniques": data.get("mitre_techniques", []),
        "attack_chains": data.get("attack_chains", []),
        "coverage": data.get("coverage", {}),
        "tactics": {k: v["name"] for k, v in TACTICS.items()},
        "technique_details": {
            k: {"name": v["name"], "severity": v["severity"]}
            for k, v in TECHNIQUES.items()
        },
    })


# ──────────────────────────────────────────────
# REST API: Attack Chains & Graph
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/attack-chains", methods=["GET"])
def api_attack_chains(case_id):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    return jsonify({
        "discovered_chains": data.get("discovered_chains", []),
        "attack_graph": data.get("attack_graph", {}),
        "attack_storyline": data.get("attack_storyline", []),
        "entity_risk_scores": data.get("entity_risk_scores", {}),
        "anomalies": data.get("anomalies", []),
        "storyline_chapters": data.get("storyline_chapters", []),
    })


# ──────────────────────────────────────────────
# REST API: Detection Rules
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/rules", methods=["GET"])
def api_get_rules(case_id):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    re_ = rule_engines.get(case_id)
    if not re_:
        return jsonify({"rules": [], "results": []})

    return jsonify({
        "rules": re_.get_rules(),
        "results": data.get("rule_results", []),
    })


@app.route("/api/<case_id>/rules", methods=["POST"])
def api_create_rule(case_id):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    re_ = rule_engines.get(case_id)
    if not re_:
        re_ = RuleEngine()
        rule_engines[case_id] = re_

    body = request.get_json(silent=True) or {}
    rule = re_.add_rule(body)

    # Re-evaluate all rules
    results = re_.evaluate_all(data["events"])
    data["rule_results"] = results

    return jsonify({"rule": rule, "results": results})


# ──────────────────────────────────────────────
# REST API: IOC Matches
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/ioc-matches", methods=["GET"])
def api_ioc_matches(case_id):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    return jsonify({
        "matches": data.get("ioc_matches", []),
        "summary": data.get("ioc_summary", {}),
    })


# ──────────────────────────────────────────────
# REST API: Bookmarks
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/bookmarks", methods=["GET"])
def api_get_bookmarks(case_id):
    return jsonify({"bookmarks": case_mgr.get_bookmarks(case_id)})


@app.route("/api/<case_id>/bookmark", methods=["POST"])
def api_add_bookmark(case_id):
    body = request.get_json(silent=True) or {}
    bm = case_mgr.add_bookmark(case_id, body)
    if not bm:
        return jsonify({"error": "Case not found"}), 404
    case_mgr.add_audit_entry(case_id, body.get("analyst", "analyst"), "Added bookmark")
    return jsonify({"bookmark": bm})


# ──────────────────────────────────────────────
# REST API: Entity Risk Timeline
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/entity-risk/<entity_type>/<entity_value>", methods=["GET"])
def api_entity_risk(case_id, entity_type, entity_value):
    data = case_store.get(case_id)
    if not data:
        return jsonify({"error": "Case not found"}), 404

    key = f"{entity_type}:{entity_value}"
    timeline = data.get("entity_risk_timeline", {}).get(key, [])
    risk = data.get("entity_risk_scores", {}).get(key, {})

    return jsonify({
        "entity": key,
        "risk_score": risk,
        "timeline": timeline,
    })


# ──────────────────────────────────────────────
# REST API: Case Management
# ──────────────────────────────────────────────
@app.route("/api/<case_id>/case", methods=["GET"])
def api_get_case(case_id):
    case = case_mgr.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(case)


@app.route("/api/<case_id>/case", methods=["POST"])
def api_update_case(case_id):
    body = request.get_json(silent=True) or {}
    case = case_mgr.update_case(case_id, **body)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    case_mgr.add_audit_entry(case_id, body.get("analyst", "analyst"), "Updated case")
    return jsonify(case)


def generate_threat_pulses(detections, anomalies, ioc_matches, attack_chains, severity):
    pulses = []
    
    # Critical Detections
    for d in detections[:2]:
        rule_name = d.get('rule') or d.get('title') or 'System Alert'
        pulses.append({"message": f"CORRELATION: {rule_name}", "severity": d.get('severity', 'info').upper()})
    
    # Anomalies
    for a in anomalies[:1]:
        pulses.append({"message": f"NOMALY: {a.get('description', 'Suspicious activity pattern')}", "severity": "HIGH"})

    # IOCs
    if ioc_matches:
        pulses.append({"message": f"INTEGRITY: Match found for host {ioc_matches[0].get('hostname', 'unknown')}", "severity": "CRITICAL"})

    # Attack Chains
    if attack_chains:
        pulses.append({"message": f"CHAIN: Progression through {len(attack_chains)} kill-chain steps", "severity": "MEDIUM"})

    # Default if empty
    if not pulses:
        pulses.append({"message": "SYSTEM: Baseline telemetry stable. No active intrusions.", "severity": "OK"})
    
    return pulses

if __name__ == "__main__":
    app.run(debug=True)
