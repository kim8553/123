# Extraction note

The outer split ZIP uses four ordered volumes. Concatenating the raw volumes and reading the first member's raw DEFLATE stream produced an inner ZIP of 669,978,178 bytes. Validate the inner archive with a ZIP CRC pass before treating every archived file as intact. Never use file names or literal strings alone as proof of packet semantics.
