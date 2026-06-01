# Contributor: Trieu Truong <quangtrieu1312@gmail.com>
# Maintainer: Trieu Truong <quangtrieu1312@gmail.com>
pkgname=tmasque
pkgver=%%PKGVER%%
pkgrel=%%PKGREL%%
pkgdesc="MASQUE VPN client (IP-over-HTTP3/QUIC, multi-client)"
url="https://github.com/quangtrieu1312/tmasque"
arch="x86_64 aarch64"
license="MIT"
depends="iproute2"
makedepends=""
options="!check !strip"  # pre-built binary requires NET_ADMIN at runtime
subpackages="$pkgname-openrc:openrc:all"
source="
	tmasque
	tmasque.conf.template
	tmasque.initd
"
builddir="$srcdir"

build() {
	:
}

package() {
	install -Dm755 "$builddir"/tmasque \
		"$pkgdir"/usr/bin/tmasque

	install -Dm644 "$builddir"/tmasque.conf.template \
		"$pkgdir"/etc/tmasque/tmasque.conf.template

	install -dm755 "$pkgdir"/etc/tmasque/certs
	install -dm750 "$pkgdir"/var/log/

	# default_openrc() will automatically split this into the -openrc subpackage
	install -Dm755 "$builddir"/tmasque.initd \
		"$pkgdir"/etc/init.d/tmasque
}

openrc() {
	pkgdesc="$pkgdesc (OpenRC init scripts)"
	install_if="$pkgname=$pkgver-r$pkgrel openrc"
	default_openrc
}
