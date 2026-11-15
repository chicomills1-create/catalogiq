"""CatalogIQ — catalog parsing + the FACT LOCK draft engine.

FACT LOCK (charter guardrail): a draft is composed ONLY from values present in
the merchant's own row. A canonical field that is absent or empty is listed in
`missing` and rendered as a flag — never invented, never approximated.
Deterministic rules composer; no external calls.
"""
import csv, io, re, zipfile
import xml.etree.ElementTree as ET

CANONICAL = ["sku", "name", "brand", "material", "dimensions", "weight",
             "color", "features", "price", "category", "description"]

SYNONYMS = {
    "sku": ["sku", "item", "itemnumber", "itemno", "partnumber", "partno",
            "productcode", "code", "mpn", "style", "model"],
    "name": ["name", "productname", "title", "producttitle", "itemname",
             "product", "description1"],
    "brand": ["brand", "manufacturer", "vendor", "make", "label"],
    "material": ["material", "fabric", "composition", "madeof", "substrate"],
    "dimensions": ["dimensions", "dimension", "size", "sizes", "dims",
                   "measurements", "measurement", "lxwxh"],
    "weight": ["weight", "wt", "lbs", "weightlbs", "weightkg"],
    "color": ["color", "colour", "finish", "colorfinish"],
    "features": ["features", "feature", "bullets", "bulletpoints", "highlights",
                 "keyfeatures", "details"],
    "price": ["price", "cost", "msrp", "retail", "unitprice", "listprice"],
    "category": ["category", "cat", "department", "type", "producttype",
                 "collection"],
    "description": ["description", "desc", "longdescription", "about",
                    "productdescription", "notes"],
}
# fields whose absence is a fact-lock flag on the draft
FLAG_FIELDS = ["brand", "material", "dimensions", "features", "category",
               "description"]


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h).lower())


def guess_mapping(columns):
    norm_cols = {_norm(c): c for c in columns}
    mapping = {}
    for canon, syns in SYNONYMS.items():
        for s in syns:
            if s in norm_cols:
                mapping[canon] = norm_cols[s]
                break
    return mapping


def parse_csv(data: bytes):
    text = data.decode("utf-8-sig", errors="replace")
    rdr = csv.DictReader(io.StringIO(text))
    cols = rdr.fieldnames or []
    rows = [{c: (r.get(c) or "").strip() for c in cols} for r in rdr]
    return cols, [r for r in rows if any(r.values())]


NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def parse_xlsx(data: bytes):
    zf = zipfile.ZipFile(io.BytesIO(data))
    shared = []
    if "xl/sharedStrings.xml" in zf.namelist():
        root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
        for si in root.findall("m:si", NS):
            shared.append("".join(t.text or "" for t in si.iter(
                "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t")))
    sheet_name = "xl/worksheets/sheet1.xml"
    if sheet_name not in zf.namelist():
        sheet_name = [n for n in zf.namelist()
                      if n.startswith("xl/worksheets/sheet")][0]
    root = ET.fromstring(zf.read(sheet_name))
    grid = []
    for row in root.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}row"):
        cells = []
        for c in row.findall("m:c", NS):
            t = c.get("t")
            v = c.find("m:v", NS)
            isn = c.find("m:is", NS)
            if t == "s" and v is not None:
                cells.append(shared[int(v.text)])
            elif isn is not None:
                cells.append("".join(x.text or "" for x in isn.iter(
                    "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t")))
            elif v is not None:
                cells.append(v.text or "")
            else:
                cells.append("")
        grid.append(cells)
    if not grid:
        return [], []
    cols = [str(h).strip() for h in grid[0]]
    rows = []
    for g in grid[1:]:
        g = (g + [""] * len(cols))[:len(cols)]
        rows.append({cols[i]: str(g[i]).strip() for i in range(len(cols))})
    return cols, [r for r in rows if any(r.values())]


def parse_upload(data: bytes, filename: str):
    name = (filename or "").lower()
    if name.endswith(".xlsx"):
        return parse_xlsx(data)
    return parse_csv(data)  # csv / tsv-as-csv / txt default


def get(row, mapping, canon):
    col = mapping.get(canon)
    if not col:
        return ""
    return (row.get(col) or "").strip()


def compose_draft(row, mapping):
    """Return (title, description, seo_title, facts, missing) — FACT LOCKED."""
    facts = {c: get(row, mapping, c) for c in CANONICAL}
    missing = [c for c in FLAG_FIELDS if not facts[c]]

    title_bits = [facts["brand"], facts["name"]]
    title = " ".join(b for b in title_bits if b).strip()
    if facts["material"] and facts["material"].lower() not in title.lower():
        title = (title + " — " + facts["material"]).strip(" —")
    if not title:
        title = facts["sku"] or "Untitled product"

    sentences = []
    if facts["description"]:
        sentences.append(facts["description"].rstrip(".") + ".")
    if facts["material"]:
        sentences.append(f"Made from {facts['material']}.")
    if facts["dimensions"]:
        sentences.append(f"Dimensions: {facts['dimensions']}.")
    if facts["weight"]:
        sentences.append(f"Weight: {facts['weight']}.")
    if facts["color"]:
        sentences.append(f"Color/finish: {facts['color']}.")
    bullets = []
    if facts["features"]:
        bullets = [b.strip() for b in re.split(r"[;|•\n]", facts["features"])
                   if b.strip()]
    desc = " ".join(sentences)
    if bullets:
        desc = (desc + "\n\nFeatures:\n" + "\n".join("• " + b for b in bullets)).strip()
    if not desc:
        desc = "(No description facts supplied — flagged, not invented.)"

    seo = title + (f" | {facts['category']}" if facts["category"] else "")
    return title, desc, seo, facts, missing
