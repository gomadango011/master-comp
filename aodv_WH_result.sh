#!/bin/bash

# 実行対象のNS3プログラム
PROGRAM="aodv_WH_3"

# 実行サイズのリスト
SIZES=(300 400 500 600)

#WHリンクの長さ
WH_SIZES=(150 200 250 300 350)

#待ち時間
WAIT_TIME=(0.3 0.4 0.5 0.6 0.7)

#エンド間距離
END_DISTANCE=(500 600 700 800)

# シミュレーション時間（秒）
TIME=40

# 実行回数
RUN_COUNT=20

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

#ノード数とWHリンクの長さを変えながら実行
for SIZE in "${SIZES[@]}"; do
    # サイズごとにサブディレクトリを作成
    # SIZE_DIR="${new_dir}/node_${SIZE}"
    # mkdir -p "$SIZE_DIR"

    #WHリンクの長さを変更
    for WH_SIZE in "${WH_SIZES[@]}"; do
        #WHリンクの長さごとのディレクトリを作成
        SIZE_DIR="${new_dir}/node_${SIZE}/${SIZE}_WH${WH_SIZE}"
        mkdir -p "$SIZE_DIR"

         # 10回シミュレーションを実行
        for ((i=1; i<=RUN_COUNT; i++)); do
            echo "Running simulation with size=$SIZE, WHの長さ=$WH_SIZE iteration=$i"
        
            #評価結果を出力するファイル名を作成
            DEF="${SIZE_DIR}/packet_num_${i}.txt"
            ./ns3 run "${PROGRAM} --size=${SIZE} --WH_size=${WH_SIZE} --time=$TIME --result_file="${DEF}" --iteration=$i > log_node${SIZE}_WH${WH_SIZE}.txt 2>&1"
        
            # 実行失敗時のエラーハンドリング
            if [ $? -ne 0 ]; then
                echo "Simulation failed for size=$SIZE, iteration=$i"
                exit 1
            fi
        done
        
    done

    #検知待機時間を変更
    for WAIT in "${WAIT_TIME[@]}"; do
        #待機時間ごとのディレクトリを作成
        SIZE_DIR="${new_dir}/node_${SIZE}/${SIZE}_wait${WAIT}"
        mkdir -p "$SIZE_DIR"

         # 10回シミュレーションを実行
        for ((i=1; i<=RUN_COUNT; i++)); do
            echo "Running simulation with size=$SIZE, wait_time=$WAIT iteration=$i"
        
            #評価結果を出力するファイル名を作成
            DEF="${SIZE_DIR}/packet_num_${i}.txt"
            ./ns3 run "${PROGRAM} --size=${SIZE} --wait_time=${WAIT} --time=$TIME --result_file="${DEF}" --iteration=$i > log_node${SIZE}_wait${WAIT}.txt 2>&1"
        
            # 実行失敗時のエラーハンドリング
            if [ $? -ne 0 ]; then
                echo "Simulation failed for size=$SIZE, iteration=$i"
                exit 1
            fi
        done
        
    done

done

#エンド間と検知待機時間を変更した場合の結果を保持するためのディレクトリ
end_DIR="${new_dir}/end_wait"
mkdir -p "$end_DIR"

#end間距離と検知待機時間を変更
for DISTANCE in "${END_DISTANCE[@]}"; do
    #エンド間距離ごとのディレクトリを作成
    SIZE_DIR="${end_DIR}/ditance_${DISTANCE}"
    mkdir -p "$SIZE_DIR"

    #検知待機時間を変更
    for WAIT in "${WAIT_TIME[@]}"; do
        #待機時間ごとのディレクトリを作成
        DIS_DIR="${SIZE_DIR}/E${DISTANCE}_wait${WAIT}"
        mkdir -p "$DIS_DIR"

         # 10回シミュレーションを実行
        for ((i=1; i<=RUN_COUNT; i++)); do
            echo "Running simulation with end_distance=$DISTANCE, wait_time=$WAIT iteration=$i"
        
            #評価結果を出力するファイル名を作成
            DEF="${DIS_DIR}/packet_num_${i}.txt"
            ./ns3 run "${PROGRAM} --end_distance=${DISTANCE} --wait_time=${WAIT} --time=$TIME --result_file="${DEF}" --iteration=$i > log_end${DISTANCE}_wait${WAIT}.txt 2>&1"
        
            # 実行失敗時のエラーハンドリング
            if [ $? -ne 0 ]; then
                echo "Simulation failed for end_distance=$DISTANCE, wait_time=$WAIT, iteration=$i"
                exit 1
            fi
        done
    done
    
done

echo "All simulations completed. Results saved in $RESULTS_BASE_DIR."

