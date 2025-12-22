#!/bin/bash

PROGRAM="master_comp"

# パラメータ
SIZES=(300 400 500 600)
WH_SIZES=(150 200 250 300)
END_DISTANCE=(500 600 700 800)

TIME=20
RUN_COUNT=20

# ==========================
# 結果ディレクトリ
# ==========================
# ==========================
# 結果ディレクトリ
# ==========================
BASE_ROOT="results"
BASE_NAME="raw"

BASE_DIR="${BASE_ROOT}/${BASE_NAME}"

if [ -d "$BASE_DIR" ]; then
  idx=2
  while [ -d "${BASE_ROOT}/${BASE_NAME}${idx}" ]; do
    idx=$((idx + 1))
  done
  BASE_DIR="${BASE_ROOT}/${BASE_NAME}${idx}"
fi

WH_DIR="${BASE_DIR}/wh_detection"
FP_DIR="${BASE_DIR}/false_positive"
MSG_DIR="${BASE_DIR}/msg_size"
RT_DIR="${BASE_DIR}/route_time"

mkdir -p "$WH_DIR" "$FP_DIR" "$MSG_DIR" "$RT_DIR"

# ==========================
# 1. WH検知率（WHリンク長）
# ==========================
for ((i=1; i<=RUN_COUNT; i++)); do

  OUT="${WH_DIR}/wh_nodes400_whL600_dist600_seed${i}.csv"

  echo "[WH Detection] nodes=400 whL=600 run=$i"

  ./ns3 run "${PROGRAM} \
    --size=400 \
    --WH_size=600 \
    --end_distance=600 \
    --time=${TIME} \
    --iteration=${i} \
    --result_file=${OUT}"
done

for ((i=1; i<=RUN_COUNT; i++)); do

  OUT="${WH_DIR}/wh_nodes400_whL500_dist600_seed${i}.csv"

  echo "[WH Detection] nodes=400 whL=500 run=$i"

  ./ns3 run "${PROGRAM} \
    --size=400 \
    --WH_size=500 \
    --end_distance=600 \
    --time=${TIME} \
    --iteration=${i} \
    --result_file=${OUT}"
done

echo "All simulations completed."
echo "Results saved under results/raw/"
