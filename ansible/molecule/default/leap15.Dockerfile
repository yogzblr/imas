# openSUSE Leap 15.6 with systemd as PID 1 (Test Kitchen's dokken image, the
# one packaging/test/rpm-service-lifecycle.sh uses) plus the Python Ansible
# needs, which it lacks.
FROM dokken/opensuse-leap-15.6
RUN zypper --non-interactive install --no-recommends python3 python3-xml \
 && zypper clean --all
CMD ["/usr/lib/systemd/systemd"]
