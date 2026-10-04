# Sourced by bash or rush with the model's command in $1.
GEARS_SH_STATE=$GEARS_SH_STATE_DIR
if [ -f "$GEARS_SH_STATE/env.sh" ]; then
    . "$GEARS_SH_STATE/env.sh" || exit 1
fi
PATH=$GEARS_SH_FIXED_PATH
export PATH
if [ -f "$GEARS_SH_STATE/cwd" ]; then
    IFS= read -r GEARS_SH_SAVED_CWD < "$GEARS_SH_STATE/cwd" || exit 1
    cd "$GEARS_SH_SAVED_CWD" || cd "$GEARS_WORKSPACE" || exit 1
fi

eval "$1"
GEARS_SH_STATUS=$?
umask 077
pwd > "$GEARS_SH_STATE/cwd.pending" || exit 1
export -p > "$GEARS_SH_STATE/env.pending" || exit 1
exit "$GEARS_SH_STATUS"
