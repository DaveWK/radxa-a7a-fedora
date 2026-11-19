# SPDX-License-Identifier: GPL-2.0-only
# shellcheck shell=bash
#
# The Fedora release an image or package build targets. Sourced by
# mkdevcard.sh and the build-*rpms.sh scripts (TOP set).
#
#   FEDORA_RELEASE=45        (default) the stable line: repositories fedora +
#                            updates, packages .fc45, paths as before
#   FEDORA_RELEASE=rawhide   Fedora Rawhide: one repository (rawhide), the
#                            repository file in fedora/repos.d/rawhide,
#                            packages .fc$FEDORA_RAWHIDE_VERSION, and every
#                            default output path suffixed -rawhide, so the two
#                            builds never share a directory or a package list
#   FEDORA_RELEASE=<N>       another numbered release: as 45, paths suffixed -N
#
# Sets:
#   RELEASEVER      dnf's --releasever
#   RELEASE_NUM     the release number in package dist tags (.fcN) and kernel
#                   version strings; Rawhide's is FEDORA_RAWHIDE_VERSION
#   RELEASE_SUFFIX  "" for 45, else "-<release>": appended to default paths
#   RELEASE_REPOS   dnf --repo arguments (an array)
#   RELEASE_PACKAGES  packages only that release's image needs (an array)
#   RELEASE_LABEL   ext4 label of the root filesystem (at most 16 bytes)
#   DIST            rpm dist tag, unless set by the caller
#   REPOSDIR        dnf reposdir, unless set by the caller

FEDORA_RELEASE=${FEDORA_RELEASE:-45}
# The number Rawhide currently is (its packages are .fcN). Bump at each
# Fedora branch point; the builder uses this for rawhide package selection.
FEDORA_RAWHIDE_VERSION=${FEDORA_RAWHIDE_VERSION:-46}
RELEASE_PACKAGES=()
case $FEDORA_RELEASE in
rawhide)
    RELEASEVER=rawhide
    RELEASE_NUM=$FEDORA_RAWHIDE_VERSION
    RELEASE_SUFFIX=-rawhide
    RELEASE_REPOS=(--repo=rawhide)
    # Rawhide's repository definitions are a package of their own; without
    # it the board has fedora.repo and updates.repo for a release number
    # that has no such repositories yet.
    RELEASE_PACKAGES=(fedora-repos-rawhide)
    RELEASE_LABEL=FedoraRaw-root
    REPOSDIR=${REPOSDIR:-$TOP/fedora/repos.d/rawhide}
    ;;
*)
    [[ $FEDORA_RELEASE =~ ^[1-9][0-9]+$ ]] || {
        echo "invalid FEDORA_RELEASE '$FEDORA_RELEASE' (a release number or rawhide)" >&2
        exit 2
    }
    RELEASEVER=$FEDORA_RELEASE
    RELEASE_NUM=$FEDORA_RELEASE
    RELEASE_SUFFIX=
    [ "$FEDORA_RELEASE" = 45 ] || RELEASE_SUFFIX=-$FEDORA_RELEASE
    RELEASE_REPOS=(--repo=fedora --repo=updates)
    RELEASE_LABEL=Fedora$RELEASEVER-root
    # Fedora's own repository files: /usr/share/dnf5/repos.d on a Fedora 45
    # host, /etc/yum.repos.d before that.
    REPOSDIR=${REPOSDIR:-$([ -f /usr/share/dnf5/repos.d/fedora.repo ] && echo /usr/share/dnf5/repos.d || echo /etc/yum.repos.d)}
    ;;
esac
[[ $RELEASE_NUM =~ ^[1-9][0-9]+$ ]] || {
    echo "invalid FEDORA_RAWHIDE_VERSION '$RELEASE_NUM'" >&2
    exit 2
}
DIST=${DIST:-.fc$RELEASE_NUM}

# The kmod set cubie-a7a-kmods builds for a kernel version (its dkms.conf and
# /usr/libexec/cubie-a7a/kernel hold the same table):
#   7.2, 7.3  A733 pinctrl as a module, sun6i-dma override
#   7.4       A733 pinctrl built into the kernel, stock sun6i-dma
# Prints the modules that must come from extra/ and be in the initramfs,
# then "--", then the stock modules the initramfs needs as well.
cubie_boot_kmods() {
    case $1 in
    7.2.* | 7.3.*) echo "sun60i-a733-ccu pinctrl-sun60i-a733 axp318w axp318-regulator sun6i-dma -- sunxi-mmc i2c-mv64xxx" ;;
    *) echo "sun60i-a733-ccu axp318w axp318-regulator -- sun6i-dma sunxi-mmc i2c-mv64xxx" ;;
    esac
}

# Check the staged root's selected board modules, not the initramfs contents.
cubie_check_root_kmods() {
    local root=$1 version=$2 boot module path
    local -a board
    boot=$(cubie_boot_kmods "$version")
    read -ra board <<<"${boot%% -- *}"
    for module in "${board[@]}" dwmac-sun55i; do
        path=$(chroot "$root" modinfo -k "$version" -n "$module") || return 1
        case "$path" in
        "/lib/modules/$version/extra/"* | "/usr/lib/modules/$version/extra/"*) ;;
        *) return 1 ;;
        esac
        chroot "$root" test -f "$path" || return 1
    done
    case "$version" in
    7.2.* | 7.3.*) ;;
    *) grep -qx 'CONFIG_PINCTRL_SUN60I_A733=y' "$root/usr/lib/modules/$version/config" || return 1 ;;
    esac
}

# Sourced by mkdevcard.sh and build-*rpms.sh: reference the
# exported release variables here so shellcheck sees them used without a disable.
: "${FEDORA_RELEASE}" "${FEDORA_RAWHIDE_VERSION}" "${RELEASEVER}" "${RELEASE_NUM}" \
    "${RELEASE_SUFFIX}" "${RELEASE_REPOS[*]}" "${RELEASE_PACKAGES[*]}" \
    "${RELEASE_LABEL}" "${DIST}" "${REPOSDIR}"
