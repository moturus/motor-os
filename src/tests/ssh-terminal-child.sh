#!/system/bin/rush

echo STREAM_READY
read -r value
printf 'STREAM_ONE=<%s>\n' "$value"
read -r value
printf 'STREAM_TWO=<%s>\n' "$value"
