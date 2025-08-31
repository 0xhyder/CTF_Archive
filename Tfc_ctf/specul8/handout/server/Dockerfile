FROM ubuntu:24.10

RUN apt update && apt install -y \
    python3 \
    python3-pip \
    socat

RUN useradd ctf
USER ctf

WORKDIR /home/ctf

COPY --chown=ctf:ctf . /home/ctf
RUN chmod +x ./entrypoint.sh

EXPOSE 1337

CMD ["/home/ctf/entrypoint.sh"]