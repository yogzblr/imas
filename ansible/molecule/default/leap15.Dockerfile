# openSUSE Leap 15.6 with systemd as PID 1 (Test Kitchen's dokken image, the
# one packaging/test/rpm-service-lifecycle.sh uses) plus the Python Ansible
# needs, which it lacks.
#
# Leap's own python3 is 3.6, which current ansible-core (2.17 and later) no
# longer runs modules on, so this installs the python311 stack Leap ships
# alongside it; Ansible's interpreter discovery picks /usr/bin/python3.11
# ahead of /usr/bin/python3. The import check fails the build here, rather
# than at the first zypper task, if the XML parser the zypper modules need is
# missing.
FROM dokken/opensuse-leap-15.6
RUN zypper --non-interactive --gpg-auto-import-keys refresh \
 && zypper --non-interactive install --no-recommends python311 \
 && zypper clean --all \
 && python3.11 -c 'import xml.dom.minidom, xml.parsers.expat'
CMD ["/usr/lib/systemd/systemd"]
