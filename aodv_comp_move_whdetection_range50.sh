#!/bin/bash

PROGRAM="master_comp_range50"

# パラメータ
SIZES=(300 400 500 600)
WH_SIZES=(150 200 250 300)
END_DISTANCE=(500 600 700 800)

TIME=20
RUN_COUNT=20

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
for WH in "${WH_SIZES[@]}"; do
  for ((i=1; i<=RUN_COUNT; i++)); do

    OUT="${WH_DIR}/wh_nodes400_whL${WH}_dist600_seed${i}.csv"

    echo "[WH Detection] nodes=400 whL=$WH run=$i"

    ./ns3 run "${PROGRAM} \
      --size=400 \
      --WH_size=${WH} \
      --end_distance=600 \
      --time=${TIME} \
      --iteration=${i} \
      --result_file=${OUT}"
  done
done

# # ==========================
# # 2. 正常ノード誤検知率（ノード数 × 待ち時間）
# # ==========================
# for SIZE in "${SIZES[@]}"; do
#   for ((i=1; i<=RUN_COUNT; i++)); do

#     OUT="${FP_DIR}/fp_nodes${SIZE}_dist600_whL200_seed${i}.csv"

#     echo "[False Positive] nodes=$SIZE run=$i"

#     ./ns3 run "${PROGRAM} \
#       --size=${SIZE} \
#       --WH_size=300 \
#       --end_distance=600 \
#       --time=${TIME} \
#       --iteration=${i} \
#       --result_file=${OUT}" \
#       > "${OUT}.stdout" 2>&1 || exit 1
#   done
# done

# ==========================
# 3. 総メッセージサイズ（ノード数）
# ==========================
# for SIZE in "${SIZES[@]}"; do
#   for ((i=1; i<=RUN_COUNT; i++)); do

#     OUT="${MSG_DIR}/msg_nodes${SIZE}_dist600_whL200_seed${i}.csv"

#     echo "[Message Size] nodes=$SIZE run=$i"

#     ./ns3 run "${PROGRAM} \
#       --size=${SIZE} \
#       --WH_size=200 \
#       --end_distance=600 \
#       --time=${TIME} \
#       --iteration=${i} \
#       --result_file=${OUT}" \
#       > "${OUT}.stdout" 2>&1 || exit 1
#   done
# done

# ==========================
# 4. 経路作成時間（距離 × 待ち時間）
# ==========================
# for DIST in "${END_DISTANCE[@]}"; do
#   for ((i=1; i<=RUN_COUNT; i++)); do

#     OUT="${RT_DIR}/rt_nodes400_dist${DIST}_whL300_seed${i}.csv"

#     echo "[Route Time] dist=$DIST run=$i"

#     ./ns3 run "${PROGRAM} \
#       --size=400 \
#       --WH_size=300 \
#       --end_distance=${DIST} \
#       --time=${TIME} \
#       --iteration=${i} \
#       --result_file=${OUT}" \
#       > "${OUT}.stdout" 2>&1 || exit 1
#   done
# done

echo "All simulations completed."
echo "Results saved under results/raw/"
