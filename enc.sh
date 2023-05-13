#!/bin/bash

config_path="$HOME/.config/encrypted"
key_length=32

file_encode() { openssl enc -in "$1" -out "$2" -aes-256-cbc -salt -pass "pass:$3" -pbkdf2 -md sha512 -iter 69420; }
file_decode() { openssl enc -in "$1" -out "$2" -aes-256-cbc -d -pass "pass:$3" -pbkdf2 -md sha512 -iter 69420; }
str_encode() { echo "$1" | openssl enc -aes-256-cbc -salt -pass "pass:$2" -pbkdf2 -md sha512 -iter 69420 | base64 -w 0; }
str_decode() { echo "$1" | base64 -d | openssl enc -aes-256-cbc -d -pass "pass:$2" -pbkdf2 -md sha512 -iter 69420; }

helper() {
  echo
  echo "Usage:"
  echo "enc [-s|--string] <file to encode>"
  echo "enc <text to encode/decode>"
  echo "enc [-h|--help]"
  echo
  echo "Options:"
  echo "  -h, --help    Show this help message and exit"
  echo "  -s, --string  Encrypt a file and encode the result in base64"
  echo
}

initialize_config() {
  [ ! -f "$config_path" ] && mkdir -p "$(dirname "$config_path")"
  touch "$config_path"
  chmod 600 "$config_path"
  while true; do
    read -s -p "Enter new key password: " password && echo
    read -s -p "Confirm new key password: " password_confirm && echo
    [ "$password" == "$password_confirm" ] && break || echo "Passwords do not match"
  done
  random_key=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$key_length")
  encrypted_key=$(str_encode "$random_key" "$password")
  echo "key=\"$encrypted_key\"" > "$config_path"
}

enc() {
  [[ "$1" = '-h' || "$1" = '--help' ]] && helper && return
  [ ! -f "$config_path" ] && initialize_config
  source "$config_path"

  while true; do
    if [ -z "$password_confirm" ]; then
      unset password_confirm
      read -s -p "Enter key password: " password && echo
    fi
    local key=$(str_decode "$key" "$password" 2>&1)
    [ "${key:0:11}" = "bad decrypt" ] || break
    echo "Invalid password."
  done

  if [[ "$1" = "-s" || "$1" = "--string" ]]; then
    input=$(cat "${@:2}")
  elif [ -n "$1" ]; then input="$@"
  else read -p "> " input; fi

  if [[ -f "$input" || -d "$input" ]]; then
    local old_path="$PWD"
    local input=$(readlink -f "$input")
    local path="${input%/*}"
    local file="${input##*/}"
    local name="${file%.*}"
    [[ "$file" = *'.'* ]] && local ext="${file##*.}"
    if [ "$ext" = 'bin' ]; then
      out_path="${path/$HOME/\~}"
      echo "Decrypting inside $out_path"
      file_decode "$input" "${config_path}.tar" "$key"
      tar xf "${config_path}.tar" -C "$path"
    else
      out_path="${path/$HOME/\~}/$name.bin"
      echo "Encrypting to $out_path"
      cd "$path"
      tar cf "${config_path}.tar" "$file" 2>/dev/null
      file_encode "${config_path}.tar" "$path/$name.bin" "$key"
    fi
    rm -f "${config_path}.tar"
    cd "$old_path"
  elif str_decode "$input" "$key" >/dev/null 2>&1; then
    str_decode "$input" "$key"
  else
    str_encode "$input" "$key"
    echo
  fi
}
