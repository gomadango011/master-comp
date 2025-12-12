#!/bin/bash

# 実行対象のNS3プログラム
PROGRAM="aodv_WH_move"

# 実行サイズのリスト
SIZES=(400 500 600)

#WHリンクの長さ
WH_SIZES=(150 200 250 300 350)

#待ち時間
WAIT_TIME=(0.3 0.4 0.5 0.6 0.7)

#エンド間距離
END_DISTANCE=(500 600 700 800)

# シミュレーション時間（秒）
TIME=40

# 実行回数
RUN_COUNT=40

# 結果を保存するディレクトリのベース
RESULTS_BASE_DIR="p-log"

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

#ノード数を変更して実行
for SIZE in "${SIZES[@]}"; do
    # サイズごとにサブディレクトリを作成
    SIZE_DIR="${new_dir}/WH_150/node_${SIZE}"
    mkdir -p "$SIZE_DIR"

     # 10回シミュレーションを実行
    for ((i=1; i<=RUN_COUNT; i++)); do
        echo "Running simulation with size=$SIZE iteration=$i"
    
        #評価結果を出力するファイル名を作成
        DEF="${SIZE_DIR}/packet_num_${i}.txt"
        ./ns3 run "${PROGRAM} --size=${SIZE} --time=$TIME --WH_size=150 --result_file="${DEF}" --iteration=$i+20"
    
        # 実行失敗時のエラーハンドリング
        if [ $? -ne 0 ]; then
            echo "Simulation failed for size=$SIZE, iteration=$i"
            exit 1
        fi
    done
    
done

echo "All simulations completed. Results saved in $RESULTS_BASE_DIR."

