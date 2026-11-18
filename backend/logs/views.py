import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings
from django.utils.text import get_valid_filename
from pymongo import MongoClient
from rest_framework import status
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response

ALLOWED_EXTENSIONS = {".csv", ".json", ".txt"}
REQUIRED_COLUMNS = {"@timestamp", "source_ip", "status"}

db = MongoClient(settings.MONGO_URI)[settings.MONGO_DB]


def validate_content(ext, text):
    """Retourne (lignes_apercu, erreur)."""
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return [], "Le fichier est vide."
    if ext == ".csv":
        header = next(csv.reader(io.StringIO(lines[0])))
        missing = REQUIRED_COLUMNS - set(header)
        if missing:
            return [], f"Colonnes manquantes : {', '.join(sorted(missing))}"
    elif ext == ".json":
        try:
            event = json.loads(lines[0])
        except ValueError:
            return [], "Format JSON invalide (un objet JSON par ligne attendu)."
        missing = REQUIRED_COLUMNS - set(event)
        if missing:
            return [], f"Champs manquants : {', '.join(sorted(missing))}"
    return lines[:10], None


@api_view(["POST"])
@parser_classes([MultiPartParser])
def upload_file(request):
    f = request.FILES.get("file")
    if f is None:
        return Response({"error": "Aucun fichier envoyé (champ 'file')."},
                        status=status.HTTP_400_BAD_REQUEST)

    name = get_valid_filename(Path(f.name).name)
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return Response({"error": "Format non autorisé (CSV, JSON ou TXT)."},
                        status=status.HTTP_400_BAD_REQUEST)
    if f.size > settings.MAX_UPLOAD_SIZE:
        return Response({"error": "Fichier trop volumineux (100 Mo max)."},
                        status=status.HTTP_400_BAD_REQUEST)

    raw = f.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return Response({"error": "Encodage invalide (UTF-8 attendu)."},
                        status=status.HTTP_400_BAD_REQUEST)

    # Logstash n'envoie une ligne que si elle se termine par un retour à la ligne
    if not raw.endswith(b"\n"):
        raw += b"\n"

    preview, error = validate_content(ext, text)
    if error:
        return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)

    # Écriture dans le dossier surveillé par Logstash (fichier temporaire puis renommage)
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    final_name = f"{uuid.uuid4().hex[:8]}_{name}"
    tmp_path = upload_dir / (final_name + ".tmp")
    tmp_path.write_bytes(raw)
    os.replace(tmp_path, upload_dir / final_name)

    total = len([l for l in text.splitlines() if l.strip()])
    if ext == ".csv":
        total -= 1  # en-tête

    doc = {
        "filename": final_name,
        "file_type": ext.lstrip(".").upper(),
        "file_size": f.size,
        "upload_date": datetime.now(timezone.utc),
        "uploaded_by": "anonymous",  # remplacé par l'utilisateur connecté en S3
        "status": "pending",
        "total_logs": total,
    }
    inserted = db.uploaded_files.insert_one(doc)

    return Response({
        "id": str(inserted.inserted_id),
        "filename": final_name,
        "total_logs": total,
        "status": "pending",
        "preview": preview,
    }, status=status.HTTP_201_CREATED)