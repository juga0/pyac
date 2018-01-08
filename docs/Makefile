# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = PyAC
SOURCEDIR     = source
BUILDDIR      = build

# Internal variables.
PAPEROPT_a4     = -D latex_paper_size=a4
PAPEROPT_letter = -D latex_paper_size=letter
ALLSPHINXOPTS   = -d $(BUILDDIR)/doctrees $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) source
# the i18n builder cannot share the environment and doctrees with the others
I18NSPHINXOPTS  = $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) source
# not in auto-generated conf
SOURCEDIR       = source
IMAGEDIRS       = source/images
BUILDDIRIMAGES  = $(BUILDDIR)/html/_images
# generate SVG
PYREVERSE     = pyreverse
PYREVERSE_FLAGS = -o svg -p dhcpcanon ../dhcpcanon
# SVG to PDF conversion
SVG2PDF       = inkscape
SVG2PDF_FLAGS =

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile


UMLSVG := $(PYREVERSE) $(PYREVERSE_FLAGS);mv *.svg $(IMAGEDIRS);mkdir -p $(BUILDDIRIMAGES);cp $(IMAGEDIRS)/*.svg $(BUILDDIRIMAGES)
umlsvg:
	@echo "Generating UML SVG"
	$($UMLSVG)

# Pattern rule for converting SVG to PDF
%.pdf : %.svg
	$(SVG2PDF) -f $< -A $@
# Build a list of SVG files to convert to PDFs
PDFs := $(foreach dir, $(IMAGEDIRS), $(patsubst %.svg,%.pdf,$(wildcard $(SOURCEDIR)/$(dir)/*.svg)))

# Make a rule to build the PDFs
images:
	@echo "Generating PDFs"
	$(PDFs)


# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
