# Makefile for Sphinx documentation
#

# We want the directory where the source is, we take it from the
# directory of the makefile -- we need this in case we are building to
# a separate directory.
srcdir = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

# ok, this is a hack because some distros don't have it -- need it for
# now so the ttbl.raritan_emx module builds ok -- until we remove the
# need for the raritan SDK and just use JSON RPC.
export PYTHONPATH := $(PYTHONPATH):$(srcdir):$(srcdir)/ttbd:/usr/local/lib/python3.7/site-packages
# You can set these variables from the command line.
SPHINXOPTS    = -q -n
SPHINXBUILD   = sphinx-build-3
PAPER         =
BUILDDIR      ?= build
srcdir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Internal variables.
PAPEROPT_a4     = -D latex_paper_size=a4
PAPEROPT_letter = -D latex_paper_size=letter
ALLSPHINXOPTS   = -d $(BUILDDIR)/doctrees $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) .
# the i18n builder cannot share the environment and doctrees with the others
I18NSPHINXOPTS  = $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) source

.PHONY: help clean html dirhtml singlehtml pickle json htmlhelp qthelp devhelp epub latex latexpdf text man changes linkcheck doctest gettext

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  html       to make standalone HTML files"
	@echo "  dirhtml    to make HTML files named index.html in directories"
	@echo "  singlehtml to make a single large HTML file"
	@echo "  pickle     to make pickle files"
	@echo "  json       to make JSON files"
	@echo "  htmlhelp   to make HTML files and a HTML help project"
	@echo "  qthelp     to make HTML files and a qthelp project"
	@echo "  devhelp    to make HTML files and a Devhelp project"
	@echo "  epub       to make an epub"
	@echo "  latex      to make LaTeX files, you can set PAPER=a4 or PAPER=letter"
	@echo "  latexpdf   to make LaTeX files and run them through pdflatex"
	@echo "  text       to make text files"
	@echo "  man        to make manual pages"
	@echo "  texinfo    to make Texinfo files"
	@echo "  info       to make Texinfo files and run them through makeinfo"
	@echo "  gettext    to make PO message catalogs"
	@echo "  changes    to make an overview of all changed/added/deprecated items"
	@echo "  linkcheck  to check all external links for integrity"
	@echo "  doctest    to run all doctests embedded in the documentation (if enabled)"

clean:
	-rm -rf $(BUILDDIR)/* \
	  setup.cfg ttbd/setup.cfg ttbd/pos/setup.cfg \
	  zephyr/setup.cfg ttbd/zephyr/setup.cfg

html:
	$(SPHINXBUILD) -v -v -v -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html

dirhtml:
	$(SPHINXBUILD) -b dirhtml $(ALLSPHINXOPTS) $(BUILDDIR)/dirhtml

singlehtml:
	$(SPHINXBUILD) -b singlehtml $(ALLSPHINXOPTS) $(BUILDDIR)/singlehtml

pickle:
	$(SPHINXBUILD) -b pickle $(ALLSPHINXOPTS) $(BUILDDIR)/pickle
	@echo
	@echo "Build finished; now you can process the pickle files."

json:
	$(SPHINXBUILD) -b json $(ALLSPHINXOPTS) $(BUILDDIR)/json
	@echo
	@echo "Build finished; now you can process the JSON files."

htmlhelp:
	$(SPHINXBUILD) -b htmlhelp $(ALLSPHINXOPTS) $(BUILDDIR)/htmlhelp
	@echo
	@echo "Build finished; now you can run HTML Help Workshop with the" \
	      ".hhp project file in $(BUILDDIR)/htmlhelp."

qthelp:
	$(SPHINXBUILD) -b qthelp $(ALLSPHINXOPTS) $(BUILDDIR)/qthelp
	@echo
	@echo "Build finished; now you can run "qcollectiongenerator" with the" \
	      ".qhcp project file in $(BUILDDIR)/qthelp, like this:"
	@echo "# qcollectiongenerator $(BUILDDIR)/qthelp/timo.qhcp"
	@echo "To view the help file:"
	@echo "# assistant -collectionFile $(BUILDDIR)/qthelp/timo.qhc"

devhelp:
	$(SPHINXBUILD) -b devhelp $(ALLSPHINXOPTS) $(BUILDDIR)/devhelp
	@echo
	@echo "Build finished."
	@echo "To view the help file:"
	@echo "# mkdir -p $$HOME/.local/share/devhelp/timo"
	@echo "# ln -s $(BUILDDIR)/devhelp $$HOME/.local/share/devhelp/timo"
	@echo "# devhelp"

epub:
	$(SPHINXBUILD) -b epub $(ALLSPHINXOPTS) $(BUILDDIR)/epub
	@echo
	@echo "Build finished. The epub file is in $(BUILDDIR)/epub."

latex:
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILDDIR)/latex
	@echo
	@echo "Build finished; the LaTeX files are in $(BUILDDIR)/latex."
	@echo "Run \`make' in that directory to run these through (pdf)latex" \
	      "(use \`make latexpdf' here to do that automatically)."

latexpdf:
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILDDIR)/latex
	@echo "Running LaTeX files through pdflatex..."
	$(MAKE) -C $(BUILDDIR)/latex all-pdf
	@echo "pdflatex finished; the PDF files are in $(BUILDDIR)/latex."

text:
	$(SPHINXBUILD) -b text $(ALLSPHINXOPTS) $(BUILDDIR)/text
	@echo
	@echo "Build finished. The text files are in $(BUILDDIR)/text."

man:
	$(SPHINXBUILD) -b man $(ALLSPHINXOPTS) $(BUILDDIR)/man
	@echo
	@echo "Build finished. The manual pages are in $(BUILDDIR)/man."

texinfo:
	$(SPHINXBUILD) -b texinfo $(ALLSPHINXOPTS) $(BUILDDIR)/texinfo
	@echo
	@echo "Build finished. The Texinfo files are in $(BUILDDIR)/texinfo."
	@echo "Run \`make' in that directory to run these through makeinfo" \
	      "(use \`make info' here to do that automatically)."

info:
	$(SPHINXBUILD) -b texinfo $(ALLSPHINXOPTS) $(BUILDDIR)/texinfo
	@echo "Running Texinfo files through makeinfo..."
	make -C $(BUILDDIR)/texinfo info
	@echo "makeinfo finished; the Info files are in $(BUILDDIR)/texinfo."

gettext:
	$(SPHINXBUILD) -b gettext $(I18NSPHINXOPTS) $(BUILDDIR)/locale
	@echo
	@echo "Build finished. The message catalogs are in $(BUILDDIR)/locale."

changes:
	$(SPHINXBUILD) -b changes $(ALLSPHINXOPTS) $(BUILDDIR)/changes
	@echo
	@echo "The overview file is in $(BUILDDIR)/changes."

linkcheck:
	$(SPHINXBUILD) -b linkcheck $(ALLSPHINXOPTS) $(BUILDDIR)/linkcheck
	@echo
	@echo "Link check complete; look for any errors in the above output " \
	      "or in $(BUILDDIR)/linkcheck/output.txt."

doctest:
	$(SPHINXBUILD) -b doctest $(ALLSPHINXOPTS) $(BUILDDIR)/doctest
	@echo "Testing of doctests in the sources finished, look at the " \
	      "results in $(BUILDDIR)/doctest/output.txt."

tests:
	python3 -m unittest discover -vv

# RPM versions can't have dash (-), so use underscores (_)
# To match Python's packaging.version requirements https://packaging.python.org/en/latest/specifications/version-specifiers/:
#
#  - remove the leading v (v0.14.4562.g9df37931 -> 0.14.4562.g9df37931)
#  - remove the g in the commit number (0.14.4562.g9df37931 -> 0.14.4562.9df37931)
#  - commit number has to be dec (vs hex) so we format it as a decimal integer
#    ( 0.14.4562.9df37931 ->  0.14.4562.2649979185)
#  - awk's $1 has to be coded as $$1 so make(1) passes it as $1
export VERSION ?= $(shell git describe \
	| awk -vFS=- '{ gsub("^v", "", $$1); gsub("^g", "", $$3); printf("%s.%s.%d", $$1, $$2, strtonum("0x" $$3)); }')

export DISTRO        ?= $(shell source /etc/os-release && echo $$ID)
export DISTRONAME    ?= $(shell echo $(DISTRO) | tr A-Z a-z)
export DISTROVERSION ?= $(shell source /etc/os-release && echo $$VERSION_ID)

BASE        := $(PWD)
RPMDIR      ?= $(BASE)/dist
CONTAINER   ?= True

.FORCE:

# Make sure this file is always re-generated, since we might be
# passing a different DISTRO ... and anyway we are always remaking the
# RPMs
%.cfg: %.cfg.in .FORCE
	./setup-requirements.py -d $(DISTRONAME) -v $(DISTROVERSION) --config $@ $(dir $@)requirements.txt 

rpms-ttbd-zephyr: ttbd/zephyr/setup.cfg
	mkdir -p $(RPMDIR)
	./build_rpms.sh -d $(DISTRONAME) -v $(DISTROVERSION) -t ttbd/zephyr -p $(RPMDIR) -i $(CONTAINER)

rpms-ttbd-pos: ttbd/pos/setup.cfg
	mkdir -p $(RPMDIR)
	./build_rpms.sh -d $(DISTRONAME) -v $(DISTROVERSION) -t ttbd/pos -p $(RPMDIR) -i $(CONTAINER)

rpms-ttbd: ttbd/setup.cfg
	mkdir -p $(RPMDIR)
	./build_rpms.sh -d $(DISTRONAME) -v $(DISTROVERSION) -t ttbd -p $(RPMDIR) -i $(CONTAINER)

rpms-tcf-zephyr: zephyr/setup.cfg
	mkdir -p $(RPMDIR)
	./build_rpms.sh -d $(DISTRONAME) -v $(DISTROVERSION) -t zephyr -p $(RPMDIR) -i $(CONTAINER)

rpms-tcf: setup.cfg
	mkdir -p $(RPMDIR)
	./build_rpms.sh -d $(DISTRONAME) -v $(DISTROVERSION) -p $(RPMDIR) -i $(CONTAINER)

rpms: rpms-tcf rpms-tcf-zephyr rpms-ttbd rpms-ttbd-zephyr rpms-ttbd-pos

version:
	@echo $(VERSION)
