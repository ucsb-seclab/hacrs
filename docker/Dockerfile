FROM ubuntu
RUN ["apt-get", "update"]
RUN ["apt-get", "upgrade", "-y"]
COPY "./keyboard" "/etc/default/keyboard"
RUN ["apt-get", "install", "-y", "tightvncserver", "xserver-xorg-core", "xserver-xorg-input-all", "xserver-xorg-video-fbdev", "libx11-6", "x11-common", "x11-utils", "x11-xkb-utils", "x11-xserver-utils", "xterm", "lightdm", "openbox"]
RUN ["apt-get", "install", "-y", "websockify"]
RUN ["apt-get", "install", "-y", "python-pkg-resources"]
RUN ["apt-get", "install", "-y", "ssh"]


RUN ["mkdir", "/home/seclab"]
RUN ["mkdir", "/home/seclab/mnt"]
RUN ["useradd", "seclab", "-d", "/home/seclab", "-s", "/bin/bash"]
RUN ["chown", "-R", "seclab:seclab", "/home/seclab"]

CMD ["/bin/bash"]

