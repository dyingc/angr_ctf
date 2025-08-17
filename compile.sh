#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage: compile.sh [options] <CHALLENGE_DIR> <SEED> [OUTPUT_NAME]

Positional:
  CHALLENGE_DIR   Folder containing generate.py (e.g., 01_angr_avoid)
  SEED            Seed passed to generate.py
  OUTPUT_NAME     (optional) output filename within CHALLENGE_DIR (default: solution.bin)

Options:
  -i IMAGE        Image tag/name (default: angr-build:latest)
  -f DOCKERFILE   Dockerfile path (default: Angr_Build_Image_Dockerfile)
  -r RUNTIME      Container runtime: docker|podman (auto-detect)
  -n              Skip build step (use existing local image)
  -p              Print resolved settings and exit (dry run)
  -h              Show this help
USAGE
}

IMAGE="angr-build:latest"
DOCKERFILE="Angr_Build_Image_Dockerfile"
RUNTIME=""
SKIP_BUILD=0
DRYRUN=0

while getopts ":i:f:r:nph" opt; do
  case "$opt" in
    i) IMAGE="$OPTARG" ;;
    f) DOCKERFILE="$OPTARG" ;;
    r) RUNTIME="$OPTARG" ;;
    n) SKIP_BUILD=1 ;;
    p) DRYRUN=1 ;;
    h) usage; exit 0 ;;
    \?) echo "Error: Invalid option -$OPTARG" >&2; usage; exit 2 ;;
    :)  echo "Error: Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
  esac
done
shift $((OPTIND-1))

(( $# < 2 || $# > 3 )) && { echo "Error: need 2 or 3 args: <CHALLENGE_DIR> <SEED> [OUTPUT_NAME]" >&2; usage; exit 2; }

CHAL_DIR="$1"; shift
SEED="$1"; shift
OUTPUT_NAME="${1:-solution.bin}"

# Validate inputs
[[ -d "$CHAL_DIR" ]] || { echo "Error: challenge dir not found: $CHAL_DIR" >&2; exit 4; }
[[ -f "$CHAL_DIR/generate.py" ]] || { echo "Error: $CHAL_DIR/generate.py not found." >&2; exit 4; }
(( ! SKIP_BUILD )) && [[ ! -f "$DOCKERFILE" ]] && { echo "Error: Dockerfile not found: $DOCKERFILE" >&2; exit 5; }

# Resolve runtime
if [[ -z "$RUNTIME" ]]; then
  if command -v docker >/dev/null 2>&1; then RUNTIME="docker";
  elif command -v podman >/dev/null 2>&1; then RUNTIME="podman";
  else echo "Error: neither docker nor podman found in PATH." >&2; exit 3; fi
fi

PROJECT_ROOT="$(pwd)"
OUTPUT_FILE_HOST="$CHAL_DIR/$OUTPUT_NAME"     # for your filesystem
OUTPUT_NAME_CONT="$(basename -- "$OUTPUT_NAME")"  # passed into container
mkdir -p "$CHAL_DIR"

# Build image (uses cache)
if (( ! SKIP_BUILD )); then
  echo "[*] Building image '$IMAGE' from '$DOCKERFILE' using $RUNTIME ..."
  "$RUNTIME" build -f "$DOCKERFILE" -t "$IMAGE" "$PROJECT_ROOT"
  echo "[+] Build complete."
fi

# TTY-safe
TTY_ARGS=("-i"); [[ -t 1 ]] && TTY_ARGS=("-it")

# Dry run printout
if (( DRYRUN )); then
  cat <<EOF
Runtime    : $RUNTIME
Image      : $IMAGE
Dockerfile : $DOCKERFILE
Project    : $PROJECT_ROOT
Challenge  : $CHAL_DIR
Seed       : $SEED
Host output: $OUTPUT_FILE_HOST
Container CWD: /work/$CHAL_DIR
Command    : python3 generate.py "$SEED" "$OUTPUT_NAME_CONT"
EOF
  exit 0
fi

# Run generator with output name relative to challenge dir
exec "$RUNTIME" run --rm "${TTY_ARGS[@]}" \
  -u "$(id -u):$(id -g)" \
  -e SEED="$SEED" \
  -e OUTPUT_FILE="$OUTPUT_FILE_HOST" \
  -v "$PROJECT_ROOT":/work \
  -w "/work/$CHAL_DIR" \
  "$IMAGE" \
  python3 generate.py "$SEED" "$OUTPUT_NAME_CONT"