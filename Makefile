# Makefile for PQC Developer's Handbook PDF generation
#
# Usage:
#   make                  - Build the full PDF
#   make pdf              - Build the full PDF (alias)
#   make pdf-essentials   - Build the ~240pp Essentials Edition PDF
#   make pdf-all          - Build full + essentials editions
#   make pdf-vol1         - Build Volume 1 (Algorithms — Modules 1-7)
#   make pdf-vol2         - Build Volume 2 (Production — Modules 8-11)
#   make pdf-volumes      - Build both volumes
#   make pdf-everything   - Build full + essentials + both volumes
#   make check-deps       - Verify build prerequisites
#   make lint-currency    - Flag stale-by-design tokens (dates, versions, %)
#   make check-links      - Verify external URLs are reachable (cached 30d)
#   make maintenance      - Run lint-currency + check-links together
#   make clean            - Remove generated PDFs and intermediate HTML
#   make watch            - Watch for changes and rebuild (requires entr)
#   make help             - Show this help

# Configuration — full edition
MD_SOURCE = pqc-developers-handbook.md
PDF_OUTPUT = pqc-developers-handbook.pdf
HTML_INTERMEDIATE = pqc-developers-handbook.html
WEASY_STYLESHEET = pdf-style-weasy.css

# Configuration — essentials edition
MD_ESSENTIALS = pqc-developers-handbook-essentials.md
PDF_ESSENTIALS = pqc-developers-handbook-essentials.pdf
HTML_ESSENTIALS = pqc-developers-handbook-essentials.html

# Configuration — two-volume split
MD_VOL1 = pqc-developers-handbook-vol1.md
PDF_VOL1 = pqc-developers-handbook-vol1.pdf
HTML_VOL1 = pqc-developers-handbook-vol1.html
MD_VOL2 = pqc-developers-handbook-vol2.md
PDF_VOL2 = pqc-developers-handbook-vol2.pdf
HTML_VOL2 = pqc-developers-handbook-vol2.html

# Default target
.PHONY: all
all: pdf

# Build full PDF
.PHONY: pdf
pdf: check-deps $(PDF_OUTPUT)

# Build essentials edition PDF
.PHONY: pdf-essentials
pdf-essentials: check-deps $(PDF_ESSENTIALS)

# Build both editions
.PHONY: pdf-all
pdf-all: pdf pdf-essentials

# Two-volume split — Volume 1 (Algorithms) and Volume 2 (Production)
.PHONY: pdf-vol1
pdf-vol1: check-deps $(PDF_VOL1)

.PHONY: pdf-vol2
pdf-vol2: check-deps $(PDF_VOL2)

.PHONY: pdf-volumes
pdf-volumes: pdf-vol1 pdf-vol2

# Build everything: full + essentials + two-volume split
.PHONY: pdf-everything
pdf-everything: pdf pdf-essentials pdf-volumes

# Verify build prerequisites
.PHONY: check-deps
check-deps:
	@command -v node >/dev/null 2>&1 || { echo "ERROR: node not installed (need >= 20). See README.md"; exit 1; }
	@command -v weasyprint >/dev/null 2>&1 || { echo "ERROR: weasyprint not installed. Run: pip3 install -r requirements.txt"; exit 1; }
	@node -e "require('marked')" 2>/dev/null || { echo "ERROR: marked not installed. Run: npm install"; exit 1; }

# Full edition: source markdown -> HTML -> PDF
$(HTML_INTERMEDIATE): $(MD_SOURCE) md2pdf.js
	@echo "Converting Markdown to HTML..."
	@node md2pdf.js $(MD_SOURCE) $(WEASY_STYLESHEET) $(HTML_INTERMEDIATE)
	@echo "Done: $(HTML_INTERMEDIATE)"

$(PDF_OUTPUT): $(HTML_INTERMEDIATE) $(WEASY_STYLESHEET)
	@echo "Generating PDF with WeasyPrint..."
	@weasyprint $(HTML_INTERMEDIATE) $(PDF_OUTPUT)
	@echo "Done: $(PDF_OUTPUT)"

# Essentials edition: filter source -> HTML -> PDF
$(MD_ESSENTIALS): $(MD_SOURCE) md2pdf-essentials.js
	@echo "Filtering to Essentials Edition..."
	@node md2pdf-essentials.js $(MD_SOURCE) $(MD_ESSENTIALS)

$(HTML_ESSENTIALS): $(MD_ESSENTIALS) md2pdf.js
	@echo "Converting Essentials Markdown to HTML..."
	@node md2pdf.js $(MD_ESSENTIALS) $(WEASY_STYLESHEET) $(HTML_ESSENTIALS)

$(PDF_ESSENTIALS): $(HTML_ESSENTIALS) $(WEASY_STYLESHEET)
	@echo "Generating Essentials Edition PDF with WeasyPrint..."
	@weasyprint $(HTML_ESSENTIALS) $(PDF_ESSENTIALS)
	@echo "Done: $(PDF_ESSENTIALS)"

# Volume 1 — filter source -> HTML -> PDF
$(MD_VOL1): $(MD_SOURCE) md2pdf-volume.js volume-config.js
	@echo "Filtering to Volume 1 (Algorithms)..."
	@node md2pdf-volume.js 1 $(MD_SOURCE) $(MD_VOL1)

$(HTML_VOL1): $(MD_VOL1) md2pdf.js
	@echo "Converting Volume 1 Markdown to HTML..."
	@node md2pdf.js $(MD_VOL1) $(WEASY_STYLESHEET) $(HTML_VOL1)

$(PDF_VOL1): $(HTML_VOL1) $(WEASY_STYLESHEET)
	@echo "Generating Volume 1 PDF with WeasyPrint..."
	@weasyprint $(HTML_VOL1) $(PDF_VOL1)
	@echo "Done: $(PDF_VOL1)"

# Volume 2 — filter source -> HTML -> PDF
$(MD_VOL2): $(MD_SOURCE) md2pdf-volume.js volume-config.js
	@echo "Filtering to Volume 2 (Production)..."
	@node md2pdf-volume.js 2 $(MD_SOURCE) $(MD_VOL2)

$(HTML_VOL2): $(MD_VOL2) md2pdf.js
	@echo "Converting Volume 2 Markdown to HTML..."
	@node md2pdf.js $(MD_VOL2) $(WEASY_STYLESHEET) $(HTML_VOL2)

$(PDF_VOL2): $(HTML_VOL2) $(WEASY_STYLESHEET)
	@echo "Generating Volume 2 PDF with WeasyPrint..."
	@weasyprint $(HTML_VOL2) $(PDF_VOL2)
	@echo "Done: $(PDF_VOL2)"

# Currency lint — flag stale-by-design tokens for periodic review
.PHONY: lint-currency
lint-currency:
	@bash scripts/currency-lint.sh

# Link check — probe external URLs (with 30-day cache)
.PHONY: check-links
check-links:
	@bash scripts/check-links.sh

# Quarterly maintenance pass — run both review tools
.PHONY: maintenance
maintenance: lint-currency check-links

# Clean generated files
.PHONY: clean
clean:
	@echo "Removing PDFs and intermediate HTML..."
	@rm -f $(PDF_OUTPUT) $(HTML_INTERMEDIATE) \
	       $(PDF_ESSENTIALS) $(HTML_ESSENTIALS) $(MD_ESSENTIALS) \
	       $(PDF_VOL1) $(HTML_VOL1) $(MD_VOL1) \
	       $(PDF_VOL2) $(HTML_VOL2) $(MD_VOL2)

# Watch for changes and rebuild (requires 'entr')
.PHONY: watch
watch:
	@command -v entr >/dev/null 2>&1 || { echo "ERROR: entr not installed. Install with: sudo apt install entr"; exit 1; }
	@echo "Watching $(MD_SOURCE) and $(WEASY_STYLESHEET)..."
	@echo "Press Ctrl+C to stop"
	@ls $(MD_SOURCE) $(WEASY_STYLESHEET) md2pdf.js | entr -d $(MAKE) pdf

# Show help
.PHONY: help
help:
	@echo "PQC Developer's Handbook PDF Generator"
	@echo ""
	@echo "Targets:"
	@echo "  make                  - Build the full PDF (default)"
	@echo "  make pdf              - Build the full PDF"
	@echo "  make pdf-essentials   - Build the ~300pp Essentials Edition PDF"
	@echo "  make pdf-all          - Build full + essentials editions"
	@echo "  make pdf-vol1         - Build Volume 1 (Algorithms — Modules 1-7)"
	@echo "  make pdf-vol2         - Build Volume 2 (Production — Modules 8-11)"
	@echo "  make pdf-volumes      - Build both volumes"
	@echo "  make pdf-everything   - Build full + essentials + both volumes"
	@echo "  make check-deps       - Verify build prerequisites"
	@echo "  make lint-currency    - Flag stale-by-design tokens (dates, versions, %)"
	@echo "  make check-links      - Verify external URLs are reachable"
	@echo "  make maintenance      - Run lint-currency + check-links (quarterly)"
	@echo "  make clean            - Remove all generated PDFs and intermediates"
	@echo "  make watch            - Watch for changes and rebuild (requires entr)"
	@echo "  make help             - Show this help"
	@echo ""
	@echo "Files:"
	@echo "  Full source:     $(MD_SOURCE)"
	@echo "  Full PDF:        $(PDF_OUTPUT)"
	@echo "  Essentials PDF:  $(PDF_ESSENTIALS)"
	@echo "  Stylesheet:      $(WEASY_STYLESHEET)"
