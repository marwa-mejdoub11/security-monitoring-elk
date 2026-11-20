import ipaddress
from datetime import datetime, timezone

from django.conf import settings
from elasticsearch import Elasticsearch, TransportError
from pymongo import MongoClient
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

es = Elasticsearch(settings.ES_URL)
db = MongoClient(settings.MONGO_URI)[settings.MONGO_DB]

MAX_SIZE = 100
EXACT_FILTERS = ["status", "severity", "country", "username", "event_type", "attack_type"]


def build_query(params):
    """Construit la requête Elasticsearch. Retourne (query, filtres, erreur)."""
    must, filters = [], {}

    q = params.get("q", "").strip()
    if q:
        must.append({"match": {"message": q}})
        filters["q"] = q

    ip = params.get("ip", "").strip()
    if ip:
        try:
            ipaddress.ip_network(ip, strict=False)  # accepte une IP ou un CIDR
        except ValueError:
            return None, None, "Adresse IP invalide."
        must.append({"term": {"source_ip": ip}})
        filters["ip"] = ip

    for field in EXACT_FILTERS:
        value = params.get(field, "").strip()
        if value:
            must.append({"term": {field: value}})
            filters[field] = value

    date_range = {}
    for key, op in (("date_from", "gte"), ("date_to", "lte")):
        value = params.get(key, "").strip()
        if value:
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None, None, f"Date invalide pour {key} (format ISO 8601)."
            date_range[op] = value
            filters[key] = value
    if date_range:
        must.append({"range": {"@timestamp": date_range}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}
    return query, filters, None


@api_view(["GET"])
def search_logs(request):
    try:
        page = max(int(request.GET.get("page", 1)), 1)
        size = min(max(int(request.GET.get("size", 50)), 1), MAX_SIZE)
    except ValueError:
        return Response({"error": "page et size doivent être des entiers."},
                        status=status.HTTP_400_BAD_REQUEST)
    if page * size > 10000:
        return Response({"error": "Pagination limitée aux 10 000 premiers résultats."},
                        status=status.HTTP_400_BAD_REQUEST)

    query, filters, error = build_query(request.GET)
    if error:
        return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)

    try:
        res = es.search(index=settings.ES_INDEX, query=query,
                        sort=[{"@timestamp": "desc"}],
                        from_=(page - 1) * size, size=size,
                        track_total_hits=True)
    except TransportError:
        return Response({"error": "Elasticsearch est indisponible."},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE)

    total = res["hits"]["total"]["value"]
    results = [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]

    # Historique des recherches (RM8)
    db.search_history.insert_one({
        "username": "anonymous",  # remplacé par l'utilisateur connecté plus tard
        "filters": filters,
        "search_date": datetime.now(timezone.utc),
        "results_count": total,
    })

    return Response({
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
        "message": None if total else "Aucun résultat.",
        "results": results,
    })
@api_view(["GET"])
def list_files(request):
    files = []
    for doc in db.uploaded_files.find().sort("upload_date", -1):
        indexed = es.count(
            index=settings.ES_INDEX,
            query={"term": {"source_file": doc["filename"]}},
        )["count"]
        new_status = "indexed" if indexed >= doc["total_logs"] else "pending"
        if new_status != doc["status"]:
            db.uploaded_files.update_one({"_id": doc["_id"]},
                                         {"$set": {"status": new_status}})
        files.append({
            "id": str(doc["_id"]),
            "filename": doc["filename"],
            "file_type": doc["file_type"],
            "file_size": doc["file_size"],
            "upload_date": doc["upload_date"].isoformat() + "Z",
            "status": new_status,
            "total_logs": doc["total_logs"],
            "indexed_logs": indexed,
        })
    return Response({"total": len(files), "files": files})

@api_view(["GET"])
def stats(request):
    try:
        res = es.search(
            index=settings.ES_INDEX,
            size=0,
            track_total_hits=True,
            aggs={
                "by_status": {"terms": {"field": "status"}},
                "by_severity": {"terms": {"field": "severity"}},
                "by_country": {"terms": {"field": "country", "size": 10}},
                "top_failed_ips": {
                    "filter": {"term": {"status": "failed"}},
                    "aggs": {"ips": {"terms": {"field": "source_ip", "size": 10}}},
                },
                "per_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                    },
                    "aggs": {"by_status": {"terms": {"field": "status"}}},
                },
            },
        )
    except TransportError:
        return Response({"error": "Elasticsearch est indisponible."},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE)

    aggs = res["aggregations"]
    total = res["hits"]["total"]["value"]
    by_status = {b["key"]: b["doc_count"] for b in aggs["by_status"]["buckets"]}
    failed = by_status.get("failed", 0)
    success = by_status.get("success", 0)
    auth_total = failed + success

    return Response({
        "total_logs": total,
        "failed": failed,
        "success": success,
        "success_rate": round(success / auth_total * 100, 1) if auth_total else 0,
        "by_severity": {b["key"]: b["doc_count"] for b in aggs["by_severity"]["buckets"]},
        "by_country": {b["key"]: b["doc_count"] for b in aggs["by_country"]["buckets"]},
        "top_failed_ips": [
            {"ip": b["key"], "failures": b["doc_count"]}
            for b in aggs["top_failed_ips"]["ips"]["buckets"]
        ],
        "per_hour": [
            {
                "hour": b["key_as_string"],
                "total": b["doc_count"],
                "failed": next((s["doc_count"] for s in b["by_status"]["buckets"]
                                if s["key"] == "failed"), 0),
            }
            for b in aggs["per_hour"]["buckets"]
        ],
    })