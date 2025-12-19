#!/bin/bash

# 実行対象のNS3プログラム
PROGRAM="master_comp_nomove"

# 実行サイズのリスト
SIZES=(300 400 500 600)

#WHリンクの長さ
WH_SIZES=(150 200 250 300 350)

#エンド間距離
END_DISTANCE=(400 500 600 700)

# シミュレーション時間（秒）
TIME=20

# 実行回数
RUN_COUNT=20

# 結果を保存するディレクトリのベース
RESULTS_BASE_DIR="p-log/nomove"

#最初に使うディレクトリ名
new_dir="$RESULTS_BASE_DIR"

# カウンタの初期化
counter=1

# 同名のディレクトリが存在する限り末尾に番号を付けて更新
while [ -d "$new_dir" ]; do
  new_dir="${RESULTS_BASE_DIR}_$counter"
  ((counter++))
done

# 新しいディレクトリを作成  p_log(N)
mkdir -p "$new_dir"


# サイズごとにサブディレクトリを作成
# SIZE_DIR="${new_dir}/node_${SIZE}"
# mkdir -p "$SIZE_DIR"

#WHリンクの長さを変更
for WH_SIZE in "${WH_SIZES[@]}"; do
    #WHリンクの長さごとのディレクトリを作成
    SIZE_DIR="${new_dir}/node_400/WH${WH_SIZE}"
    mkdir -p "$SIZE_DIR"

        # 10回シミュレーションを実行
    for ((i=1; i<=RUN_COUNT; i++)); do
        echo "Running simulation with size=$SIZE, WHの長さ=$WH_SIZE iteration=$i"
    
        #評価結果を出力するファイル名を作成
        DEF="${SIZE_DIR}/packet_num_${i}.csv"
        ./ns3 run "${PROGRAM} --size=400 --WH_size=${WH_SIZE} --time=$TIME --result_file="${DEF}" --iteration=$i > log_node400_WH${WH_SIZE}.txt 2>&1"
    
        # 実行失敗時のエラーハンドリング
        if [ $? -ne 0 ]; then
            echo "Simulation failed for size=400, iteration=$i"
            exit 1
        fi
    done
done

echo "All simulations completed. Results saved in $RESULTS_BASE_DIR."

