from __future__ import annotations

import csv
import html
import re
import sys
import urllib.request
from pathlib import Path

from PIL import Image as PILImage
from pypdf import PdfReader
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Frame,
    Image,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents


ROOT = Path(__file__).resolve().parents[1]
SUBMISSION = ROOT / "submission"
SOURCE = SUBMISSION / "source"
DIST = SUBMISSION / "dist"
TMP = ROOT / "tmp" / "pdfs" / "hackathon-submission"
DIAGRAMS = TMP / "research-diagrams"

SOLUTION_MD = SOURCE / "netra-solution-document.md"
ROADMAP_MD = SOURCE / "netra-roadmap-document.md"
RESEARCH_MD = SOURCE / "netra-research-brief.md"
FORM_MD = SOURCE / "netra-form-answers.md"
CLAIMS_CSV = SOURCE / "netra-claims-matrix.csv"

SOLUTION_PDF = DIST / "NETRA_Solution_Document.pdf"
ROADMAP_PDF = DIST / "NETRA_Roadmap_Flow_Diagram.pdf"
ROADMAP_PNG = DIST / "NETRA_Roadmap_Flow_Diagram.png"
FORM_TXT = DIST / "NETRA_Form_Answers.txt"
VERIFY_REPORT = TMP / "research-submission-verification.txt"
SOLUTION_TEXT = TMP / "NETRA_Solution_Document-text-check.txt"
ROADMAP_TEXT = TMP / "NETRA_Roadmap_Flow_Diagram-text-check.txt"

NAVY = colors.HexColor("#18324A")
BLUE = colors.HexColor("#2D5F88")
TEAL = colors.HexColor("#3B7A8C")
INK = colors.HexColor("#17202A")
BODY = colors.HexColor("#2D3740")
MUTED = colors.HexColor("#66727D")
LINE = colors.HexColor("#C9D2DA")
PALE_BLUE = colors.HexColor("#EAF1F6")
PALE_GRAY = colors.HexColor("#F4F6F8")
PALE_GREEN = colors.HexColor("#E9F5EE")
PALE_AMBER = colors.HexColor("#FFF7E8")
WHITE = colors.white

REFERENCE_URLS = {
    "R1": "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    "R2": "https://csrc.nist.gov/pubs/sp/800/86/final",
    "R3": "https://csrc.nist.gov/pubs/sp/800/92/final",
    "R4": "https://www.rfc-editor.org/rfc/rfc3227",
    "R5": "https://www.wireshark.org/docs/man-pages/tshark.html",
    "R6": "https://docs.zeek.org/en/current/about.html",
    "R7": "https://docs.suricata.io/en/latest/what-is-suricata.html",
    "R8": "https://attack.mitre.org/datasources/DS0029/",
    "R9": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "R10": "https://www.scitepress.org/Papers/2018/66398/",
    "R11": "https://proceedings.neurips.cc/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html",
    "R12": "https://www.nist.gov/itl/ai-risk-management-framework",
    "R13": "https://supabase.com/docs/guides/storage/security/access-control",
}

FORM_LIMITS = {
    "Synopsis / Abstract": (120, 160),
    "Literature Review / Existing Innovation & Technology": (180, 250),
    "Your Approach to Solve the Problem": (180, 250),
    "Tools & Technologies to be Used": (100, 140),
    "Challenges / Risks in Implementing the Final Prototype": (120, 180),
    "Possible Outcome of Your Work": (120, 160),
    "Accomplishments to Date": (150, 220),
}

FIGURE_PATTERN = re.compile(r"^\[\[FIGURE:([^|\]]+)\|([^\]]+)\]\]$")


class ResearchDocTemplate(BaseDocTemplate):
    def __init__(self, *args, **kwargs):
        self.report_name = kwargs.pop("report_name")
        super().__init__(*args, **kwargs)

    def afterFlowable(self, flowable) -> None:  # noqa: N802 - ReportLab API
        if not isinstance(flowable, Paragraph):
            return
        level = getattr(flowable, "toc_level", None)
        bookmark = getattr(flowable, "bookmark_name", None)
        if level is None or bookmark is None:
            return
        text = flowable.getPlainText()
        self.canv.bookmarkPage(bookmark)
        self.canv.addOutlineEntry(text, bookmark, level=level, closed=level == 0)
        self.notify("TOCEntry", (level, text, self.page, bookmark))


def fail(message: str) -> None:
    raise RuntimeError(message)


def read_required(path: Path) -> str:
    if not path.exists():
        fail(f"Missing required source: {path}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        fail(f"Required source is empty: {path}")
    return text


def register_fonts() -> None:
    font_paths = {
        "ResearchBody": Path("C:/Windows/Fonts/times.ttf"),
        "ResearchBodyBold": Path("C:/Windows/Fonts/timesbd.ttf"),
        "ResearchBodyItalic": Path("C:/Windows/Fonts/timesi.ttf"),
        "ResearchSans": Path("C:/Windows/Fonts/segoeui.ttf"),
        "ResearchSansBold": Path("C:/Windows/Fonts/seguisb.ttf"),
    }
    for name, path in font_paths.items():
        if not path.exists():
            fail(f"Required embedded font is missing: {path}")
        pdfmetrics.registerFont(TTFont(name, str(path)))
    pdfmetrics.registerFont(TTFont("Helvetica", str(font_paths["ResearchSans"])))
    pdfmetrics.registerFontFamily(
        "ResearchBody",
        normal="ResearchBody",
        bold="ResearchBodyBold",
        italic="ResearchBodyItalic",
        boldItalic="ResearchBodyBold",
    )


def styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_label": ParagraphStyle(
            "CoverLabel",
            parent=base["Normal"],
            fontName="ResearchSansBold",
            fontSize=9,
            leading=12,
            textColor=BLUE,
            spaceAfter=8 * mm,
            letterSpacing=0.6,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=base["Title"],
            fontName="ResearchSansBold",
            fontSize=31,
            leading=37,
            textColor=NAVY,
            alignment=TA_LEFT,
            spaceAfter=6 * mm,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle",
            parent=base["Normal"],
            fontName="ResearchBody",
            fontSize=15,
            leading=21,
            textColor=BODY,
            spaceAfter=12 * mm,
        ),
        "cover_meta": ParagraphStyle(
            "CoverMeta",
            parent=base["Normal"],
            fontName="ResearchSans",
            fontSize=9.5,
            leading=15,
            textColor=MUTED,
            spaceAfter=2 * mm,
        ),
        "h1": ParagraphStyle(
            "Heading1",
            parent=base["Heading1"],
            fontName="ResearchSansBold",
            fontSize=20,
            leading=25,
            textColor=NAVY,
            spaceAfter=6 * mm,
            keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "Heading2",
            parent=base["Heading2"],
            fontName="ResearchSansBold",
            fontSize=13,
            leading=17,
            textColor=BLUE,
            spaceBefore=4 * mm,
            spaceAfter=2 * mm,
            keepWithNext=True,
        ),
        "h3": ParagraphStyle(
            "Heading3",
            parent=base["Heading3"],
            fontName="ResearchSansBold",
            fontSize=10.5,
            leading=14,
            textColor=TEAL,
            spaceBefore=3 * mm,
            spaceAfter=1.5 * mm,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontName="ResearchBody",
            fontSize=10.2,
            leading=15.2,
            textColor=BODY,
            alignment=TA_JUSTIFY,
            spaceAfter=3.2 * mm,
            allowWidows=0,
            allowOrphans=0,
        ),
        "bullet": ParagraphStyle(
            "Bullet",
            parent=base["BodyText"],
            fontName="ResearchBody",
            fontSize=10,
            leading=14.5,
            textColor=BODY,
            leftIndent=6 * mm,
            firstLineIndent=-3.5 * mm,
            bulletIndent=0,
            bulletFontName="ResearchBody",
            bulletFontSize=10,
            spaceAfter=1.5 * mm,
        ),
        "caption": ParagraphStyle(
            "Caption",
            parent=base["Normal"],
            fontName="ResearchBodyItalic",
            fontSize=8.5,
            leading=11,
            textColor=MUTED,
            alignment=TA_CENTER,
            spaceBefore=1.5 * mm,
            spaceAfter=4 * mm,
        ),
        "callout": ParagraphStyle(
            "Callout",
            parent=base["BodyText"],
            fontName="ResearchBodyItalic",
            fontSize=10.5,
            leading=15,
            textColor=NAVY,
            leftIndent=7 * mm,
            rightIndent=7 * mm,
            borderColor=BLUE,
            borderWidth=0,
            borderPadding=5 * mm,
            backColor=PALE_BLUE,
            spaceBefore=3 * mm,
            spaceAfter=5 * mm,
        ),
        "small": ParagraphStyle(
            "Small",
            parent=base["BodyText"],
            fontName="ResearchBody",
            fontSize=7.8,
            leading=10.2,
            textColor=BODY,
            spaceAfter=1 * mm,
        ),
        "toc_title": ParagraphStyle(
            "TOCTitle",
            parent=base["Title"],
            fontName="ResearchSansBold",
            fontSize=20,
            leading=25,
            textColor=NAVY,
            spaceAfter=7 * mm,
        ),
    }


def page_decor(c, doc: ResearchDocTemplate) -> None:
    width, height = A4
    c.saveState()
    c.setFillColor(WHITE)
    c.rect(0, 0, width, height, fill=1, stroke=0)
    if doc.page == 1:
        c.setFillColor(NAVY)
        c.rect(0, height - 16 * mm, width, 16 * mm, fill=1, stroke=0)
        c.setFillColor(BLUE)
        c.rect(0, 0, 7 * mm, height, fill=1, stroke=0)
    else:
        c.setStrokeColor(LINE)
        c.setLineWidth(0.5)
        c.line(19 * mm, height - 15 * mm, width - 19 * mm, height - 15 * mm)
        c.line(19 * mm, 14 * mm, width - 19 * mm, 14 * mm)
        c.setFont("ResearchSans", 7.5)
        c.setFillColor(MUTED)
        c.drawString(19 * mm, height - 11 * mm, doc.report_name.upper())
        c.drawString(19 * mm, 8.5 * mm, "KANAD S.H.I.E.L.D. 2026 | Technical research submission")
        c.drawRightString(width - 19 * mm, 8.5 * mm, str(doc.page))
    c.restoreState()


def markdown_markup(text: str) -> str:
    escaped = html.escape(text.strip())
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", r"<i>\1</i>", escaped)
    escaped = re.sub(r"`(.+?)`", r"<font name='ResearchSans'>\1</font>", escaped)
    escaped = re.sub(
        r"(https://[^\s&lt;]+)",
        r'<link href="\1" color="#2D5F88"><u>\1</u></link>',
        escaped,
    )
    return escaped


def plain_markdown(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    text = re.sub(r"[*_`]", "", text)
    text = re.sub(r"(?m)^#+\s*", "", text)
    text = re.sub(r"(?m)^[-*]\s+", "- ", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def word_count(text: str) -> int:
    return len(re.findall(r"\b[\w]+(?:[-'][\w]+)*\b", plain_markdown(text)))


def parse_table(lines: list[str], style_map: dict[str, ParagraphStyle], width: float) -> Table:
    rows: list[list[str]] = []
    for line in lines:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            continue
        rows.append(cells)
    columns = max(len(row) for row in rows)
    for row in rows:
        row.extend([""] * (columns - len(row)))
    ratios = {
        2: [0.25, 0.75],
        3: [0.18, 0.30, 0.52],
        4: [0.18, 0.24, 0.28, 0.30],
        5: [0.15, 0.13, 0.23, 0.29, 0.20],
    }.get(columns, [1 / columns] * columns)
    font_style = style_map["small"]
    data = [[Paragraph(markdown_markup(cell), font_style) for cell in row] for row in rows]
    table = Table(data, colWidths=[width * ratio for ratio in ratios], repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTNAME", (0, 0), (-1, 0), "ResearchSansBold"),
                ("BACKGROUND", (0, 1), (-1, -1), WHITE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE_GRAY]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.45, LINE),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def figure_flowables(stem: str, caption: str, style_map: dict[str, ParagraphStyle], width: float) -> list:
    path = DIAGRAMS / f"{stem}.png"
    if not path.exists():
        fail(f"Missing rendered Mermaid figure: {path}")
    with PILImage.open(path) as image:
        px_width, px_height = image.size
    max_height = 125 * mm
    scale = min(width / px_width, max_height / px_height)
    figure = Image(str(path), width=px_width * scale, height=px_height * scale)
    return [Spacer(1, 2 * mm), figure, Paragraph(markdown_markup(caption), style_map["caption"])]


def parse_markdown(text: str, style_map: dict[str, ParagraphStyle], frame_width: float) -> list:
    lines = text.splitlines()
    story: list = []
    paragraph: list[str] = []
    heading_count = 0

    def flush() -> None:
        if paragraph:
            story.append(Paragraph(markdown_markup(" ".join(paragraph)), style_map["body"]))
            paragraph.clear()

    index = 0
    while index < len(lines):
        raw = lines[index]
        line = raw.strip()
        if not line:
            flush()
            index += 1
            continue
        figure_match = FIGURE_PATTERN.match(line)
        if figure_match:
            flush()
            story.extend(figure_flowables(figure_match.group(1), figure_match.group(2), style_map, frame_width))
        elif line.startswith("# "):
            flush()
            if heading_count:
                story.append(CondPageBreak(75 * mm))
            heading_count += 1
            bookmark = f"section-{heading_count}"
            heading = Paragraph(markdown_markup(line[2:]), style_map["h1"])
            heading.toc_level = 0
            heading.bookmark_name = bookmark
            story.append(heading)
        elif line.startswith("## "):
            flush()
            bookmark = f"subsection-{heading_count}-{sum(1 for item in story if getattr(item, 'toc_level', None) == 1) + 1}"
            heading = Paragraph(markdown_markup(line[3:]), style_map["h2"])
            heading.toc_level = 1
            heading.bookmark_name = bookmark
            story.append(heading)
        elif line.startswith("### "):
            flush()
            story.append(Paragraph(markdown_markup(line[4:]), style_map["h3"]))
        elif line.startswith("> "):
            flush()
            story.append(Paragraph(markdown_markup(line[2:]), style_map["callout"]))
        elif line.startswith("| "):
            flush()
            table_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index].strip())
                index += 1
            story.append(parse_table(table_lines, style_map, frame_width))
            story.append(Spacer(1, 3 * mm))
            continue
        elif re.match(r"^[-*] ", line):
            flush()
            story.append(Paragraph(markdown_markup(line[2:]), style_map["bullet"], bulletText="-"))
        elif re.match(r"^\d+\. ", line):
            flush()
            number, content = line.split(". ", 1)
            story.append(Paragraph(markdown_markup(content), style_map["bullet"], bulletText=f"{number}."))
        else:
            paragraph.append(line)
        index += 1
    flush()
    return story


def cover_story(title: str, subtitle: str, document_type: str, style_map: dict[str, ParagraphStyle]) -> list:
    return [
        Spacer(1, 30 * mm),
        Paragraph(document_type.upper(), style_map["cover_label"]),
        Paragraph(title, style_map["cover_title"]),
        Paragraph(subtitle, style_map["cover_subtitle"]),
        Spacer(1, 10 * mm),
        Table(
            [
                [Paragraph("Prepared for", style_map["cover_meta"]), Paragraph("KANAD S.H.I.E.L.D. 2026 Student Hackathon", style_map["cover_meta"])],
                [Paragraph("Product", style_map["cover_meta"]), Paragraph("NETRA network and packet forensics prototype", style_map["cover_meta"])],
                [Paragraph("Evidence date", style_map["cover_meta"]), Paragraph("18 June 2026", style_map["cover_meta"])],
                [Paragraph("Positioning", style_map["cover_meta"]), Paragraph("Evidence-first engineering prototype; production and legal claims explicitly gated", style_map["cover_meta"])],
            ],
            colWidths=[32 * mm, 118 * mm],
            style=TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LINEABOVE", (0, 0), (-1, 0), 0.8, NAVY),
                    ("LINEBELOW", (0, -1), (-1, -1), 0.8, NAVY),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            ),
        ),
        Spacer(1, 38 * mm),
        Paragraph(
            "This document distinguishes literature-backed observations, repository evidence, analytical inference, and future work. It does not claim production readiness, certified attribution, TLS decryption, or legal admissibility.",
            style_map["callout"],
        ),
        PageBreak(),
    ]


def toc_story(style_map: dict[str, ParagraphStyle]) -> list:
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(
            "TOCLevel1",
            fontName="ResearchSansBold",
            fontSize=10,
            leading=16,
            textColor=NAVY,
            leftIndent=0,
            firstLineIndent=0,
            spaceBefore=2,
        ),
        ParagraphStyle(
            "TOCLevel2",
            fontName="ResearchBody",
            fontSize=8.5,
            leading=13,
            textColor=BODY,
            leftIndent=8 * mm,
            firstLineIndent=0,
        ),
    ]
    return [Paragraph("Table of Contents", style_map["toc_title"]), toc, PageBreak()]


def build_report(source: Path, output: Path, title: str, subtitle: str, report_name: str) -> None:
    style_map = styles()
    width, height = A4
    left = right = 19 * mm
    top = 20 * mm
    bottom = 18 * mm
    frame = Frame(left, bottom, width - left - right, height - top - bottom, id="research-frame")
    template = PageTemplate(id="research", frames=[frame], onPage=page_decor)
    doc = ResearchDocTemplate(
        str(output),
        pagesize=A4,
        leftMargin=left,
        rightMargin=right,
        topMargin=top,
        bottomMargin=bottom,
        title=title,
        author="NETRA Student Hackathon Team",
        subject="KANAD S.H.I.E.L.D. 2026 technical research submission",
        report_name=report_name,
    )
    doc.addPageTemplates([template])
    story = cover_story(title, subtitle, report_name, style_map)
    story.extend(toc_story(style_map))
    story.extend(parse_markdown(read_required(source), style_map, width - left - right))
    doc.multiBuild(story)


def load_claims() -> dict[str, dict[str, str]]:
    with CLAIMS_CSV.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    claims = {row["claim_id"]: row for row in rows}
    if len(claims) != len(rows) or len(claims) < 14:
        fail("Claims matrix is empty, incomplete, or contains duplicate IDs.")
    return claims


def validate_claims(texts: list[str], claims: dict[str, dict[str, str]]) -> list[str]:
    references = sorted(set(re.findall(r"CLM-\d{3}", "\n".join(texts))))
    missing = [claim for claim in references if claim not in claims]
    if missing:
        fail("Unresolved claim IDs: " + ", ".join(missing))
    if len(references) < 14:
        fail("The research documents do not reference the full claims matrix.")
    return references


def validate_ascii_dashes(paths: list[Path]) -> None:
    forbidden = {"\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212"}
    for path in paths:
        present = sorted(char for char in forbidden if char in read_required(path))
        if present:
            fail(f"Unicode dash found in {path.name}: {present}")


def validate_urls() -> list[str]:
    verified: list[str] = []
    for ref, url in REFERENCE_URLS.items():
        request = urllib.request.Request(url, headers={"User-Agent": "NETRA-Research-Report/2.0"})
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                status = getattr(response, "status", 200)
                if status >= 400:
                    fail(f"{ref} returned HTTP {status}: {url}")
        except Exception as exc:  # noqa: BLE001
            fail(f"Could not verify {ref}: {url} ({exc})")
        verified.append(f"{ref}: {url}")
    return verified


def validate_diagrams() -> list[Path]:
    sources = sorted((SOURCE / "diagrams").glob("*.mmd"))
    if len(sources) < 8:
        fail("Expected at least eight Mermaid source diagrams.")
    outputs: list[Path] = []
    for source in sources:
        output = DIAGRAMS / f"{source.stem}.png"
        if not output.exists() or output.stat().st_size == 0:
            fail(f"Missing rendered diagram for {source.name}. Run tools/render_hackathon_diagrams.ps1.")
        with PILImage.open(output) as image:
            if max(image.width, image.height) < 1800 or min(image.width, image.height) < 500:
                fail(f"Diagram resolution is insufficient: {output} ({image.width}x{image.height})")
        outputs.append(output)
    return outputs


def parse_form_sections(text: str) -> dict[str, str]:
    primary = text.split("# Plain-Text Copy", 1)[0]
    matches = list(re.finditer(r"(?m)^## (.+)$", primary))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(primary)
        sections[match.group(1).strip()] = primary[match.end() : end].strip()
    return sections


def build_form_text(text: str) -> list[str]:
    sections = parse_form_sections(text)
    blocks: list[str] = []
    counts: list[str] = []
    for title, (low, high) in FORM_LIMITS.items():
        if title not in sections:
            fail(f"Missing form section: {title}")
        count = word_count(sections[title])
        if not low <= count <= high:
            fail(f"{title} has {count} words; expected {low}-{high}.")
        counts.append(f"{title}: {count} words")
        blocks.extend([title.upper(), plain_markdown(sections[title])])
    FORM_TXT.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")
    return counts


def scan_for_secrets(paths: list[Path]) -> None:
    patterns = {
        "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "secret assignment": re.compile(r"(?:SERVICE_ROLE_KEY|DJANGO_SECRET_KEY|NETRA_EVIDENCE_KEY)\s*=\s*\S+", re.I),
        "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        "Windows user path": re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+", re.I),
    }
    findings: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name, pattern in patterns.items():
            if pattern.search(text):
                findings.append(f"{path.name}: {name}")
    if findings:
        fail("Potential private material found: " + "; ".join(findings))


def verify_pdf(path: Path, minimum_pages: int, maximum_pages: int, minimum_text: int) -> tuple[int, str, int, int]:
    reader = PdfReader(str(path))
    pages = len(reader.pages)
    if not minimum_pages <= pages <= maximum_pages:
        fail(f"{path.name} has {pages} pages; expected {minimum_pages}-{maximum_pages}.")
    text = "\n\n".join(page.extract_text() or "" for page in reader.pages)
    if len(text.strip()) < minimum_text:
        fail(f"{path.name} has insufficient extractable text.")
    if path.stat().st_size >= 100 * 1024 * 1024:
        fail(f"{path.name} exceeds the 100 MB form limit.")
    links = 0
    fonts: dict[str, bool] = {}
    for page in reader.pages:
        for annotation in page.get("/Annots", []):
            if annotation.get_object().get("/Subtype") == "/Link":
                links += 1
        for font_ref in page.get("/Resources", {}).get("/Font", {}).values():
            font = font_ref.get_object()
            descriptor = font.get("/FontDescriptor")
            embedded = False
            if descriptor:
                obj = descriptor.get_object()
                embedded = any(key in obj for key in ("/FontFile", "/FontFile2", "/FontFile3"))
            fonts[str(font.get("/BaseFont"))] = embedded
    unembedded = [font for font, embedded in fonts.items() if not embedded]
    if unembedded:
        fail(f"{path.name} contains unembedded fonts: {unembedded}")
    outlines = len(reader.outline)
    return pages, text, links, outlines


def main() -> int:
    DIST.mkdir(parents=True, exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)
    register_fonts()

    sources = [SOLUTION_MD, ROADMAP_MD, RESEARCH_MD, FORM_MD, CLAIMS_CSV]
    validate_ascii_dashes(sources + sorted((SOURCE / "diagrams").glob("*.mmd")))
    solution = read_required(SOLUTION_MD)
    roadmap = read_required(ROADMAP_MD)
    research = read_required(RESEARCH_MD)
    form = read_required(FORM_MD)
    claims = load_claims()
    referenced_claims = validate_claims([solution, roadmap], claims)
    verified_urls = validate_urls()
    diagram_outputs = validate_diagrams()
    scan_for_secrets([SOLUTION_MD, ROADMAP_MD, RESEARCH_MD, FORM_MD])

    # Preserve a convenient image upload option using the final roadmap Mermaid figure.
    ROADMAP_PNG.write_bytes((DIAGRAMS / "08-roadmap.png").read_bytes())

    build_report(
        SOLUTION_MD,
        SOLUTION_PDF,
        "NETRA: Evidence-First Network Forensics",
        "Technical research report, system design, validation evidence, limitations, and implementation roadmap",
        "NETRA Technical Research Report",
    )
    build_report(
        ROADMAP_MD,
        ROADMAP_PDF,
        "NETRA Implementation Roadmap and Evidence Flow",
        "Current-state assessment, gap traceability, phased delivery plan, and evidence-based release gates",
        "NETRA Roadmap and Flow Plan",
    )
    form_counts = build_form_text(form)

    solution_pages, solution_text, solution_links, solution_outlines = verify_pdf(
        SOLUTION_PDF, minimum_pages=22, maximum_pages=45, minimum_text=12000
    )
    roadmap_pages, roadmap_text, roadmap_links, roadmap_outlines = verify_pdf(
        ROADMAP_PDF, minimum_pages=7, maximum_pages=16, minimum_text=3500
    )
    SOLUTION_TEXT.write_text(solution_text, encoding="utf-8")
    ROADMAP_TEXT.write_text(roadmap_text, encoding="utf-8")
    scan_for_secrets([FORM_TXT, SOLUTION_TEXT, ROADMAP_TEXT])

    required = [
        "NETRA does not decrypt TLS payloads",
        "precision 0.625",
        "recall 1.0",
        "six training rows",
        "legal admissibility requires authority review",
        "production deployment remains gated",
    ]
    normalized = re.sub(r"\s+", " ", solution_text).lower()
    missing = [item for item in required if item.lower() not in normalized]
    if missing:
        fail("Required research statements missing from solution PDF: " + ", ".join(missing))

    report = [
        "NETRA professional research PDF verification",
        "Generated: 2026-06-18",
        f"Solution pages: {solution_pages}",
        f"Solution links: {solution_links}",
        f"Solution outline entries: {solution_outlines}",
        f"Solution bytes: {SOLUTION_PDF.stat().st_size}",
        f"Roadmap pages: {roadmap_pages}",
        f"Roadmap links: {roadmap_links}",
        f"Roadmap outline entries: {roadmap_outlines}",
        f"Roadmap bytes: {ROADMAP_PDF.stat().st_size}",
        f"Mermaid figures: {len(diagram_outputs)}",
        f"Referenced claims: {', '.join(referenced_claims)}",
        "",
        "Form answer counts:",
        *form_counts,
        "",
        "Verified references:",
        *verified_urls,
        "",
        "Embedded font check: PASS",
        "Secret and private-path scan: PASS",
        "Output size check: PASS",
    ]
    VERIFY_REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
