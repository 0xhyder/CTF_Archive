#!/bin/sh

SOURCE_PATH="/mnt/flags/flags.txt"
DEST_PATH="/home/ctf/flag.txt"

# copiem flagul
cp "$SOURCE_PATH" "$DEST_PATH"

# sterge fisierul original
rm "$SOURCE_PATH"

echo "Flagul a fost plasat din $SOURCE_PATH in $DEST_PATH"

# rulam serviciul probei si tinem dockerul up
socat \
-T20 \
TCP-LISTEN:1337,reuseaddr,fork \
EXEC:"timeout 20 python3 -u /home/ctf/server.py"
