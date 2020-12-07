# pcap ファイル から特徴を抽出するプログラム

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

- `$ npm start` とコマンドプロンプトに入力して実行する
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
