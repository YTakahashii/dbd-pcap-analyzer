# pcap ファイル から特徴を抽出するプログラム
https://github.com/YTakahashii/dbd-pcap-analyzer

## 実行する前に必要な手順

- node.js を PC にインストールする
  - v12系統をインストールしてください

  - https://qiita.com/echolimitless/items/83f8658cf855de04b9ce

- node_modules をインストール
  - `dbd-pcap-analyzer` フォルダをコマンドプロンプトで開く
  - `npm install` とコマンドプロンプトに入力して実行する

- pcap ファイルを json で export したファイルを用意して data フォルダに入れる

これで準備完了です．

## 実行する

- `npm start` とコマンドプロンプトに入力して実行する
- プログラムが終了すると，`results` フォルダに json ファイルが出力される．

## 各ファイルの説明

### `src/index.ts`

このプログラムはエントリポイントで，ここからスタートします．

### `src/models` フォルダ

オブジェクトの型を定義しています．

- `Packet.ts`
  - pcap ファイルのパケット一つ分の方を定義しています
- `GroupedMaliciousRequest.ts`
  - 悪性トラフィック 1 セットごとにリクエストパケットとレスポンスパケットを集計したデータ型

## 結果ファイルの説明
### `results/grouped_packets.json`

この集計データは，入口サイトのアクセスによって発生したリダイレクト通信からマルウェア配布サイトまでのリダイレクト通信のパケットをリクエストパケットとレスポンスパケットに分けてグループ化したものです．
以下では説明のため，このグループの単位を，「悪性通信1フロー」と呼ぶことにします．

```.jsonc
[
  {
    // 悪性通信1フロー分のパケットデータ（1つ目の悪性通信フロー）
    // requests[i] と responses[i] は対になっている． 例えばリクエストパケット1番目の requests[0] のレスポンスは responses[0]である．
    // したがって各悪性通信フローにおけるrequests.lengthとresponses.lengthは等しい．
    requests: [ // 1つ目の悪性通信フローのリクエストパケット
      {
        // パケットデータ
        '_index': '...',
        ...
      },
      {
        
      },
    ],
    responses: [ // 1つ目の悪性通信フローのレスポンスパケット
      {
        // パケットデータ
        '_index': '...',
        ...
      },
      {
        
      }
    ]
  },
  {
    // 悪性通信1フロー分のパケットデータ（2つ目の悪性通信フロー）
    requests: [
      
    ],
    responses: [
    
    ]
  },
]
```
