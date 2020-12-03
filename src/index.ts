// ファイル読み込み
import fs from 'fs';
const pcapPackets = require('data/20100308.json');
const entranceSiteUrlTxt = fs.readFileSync('data/url20100308.txt', 'utf-8');
const entranceSiteUrlList = entranceSiteUrlTxt.split('\n');

// 自作の集計関数の読み込み
import { groupPerMaliciousTraffic } from './groupPerMaliciousTraffic';
import { aggregateWebHierarchy } from './aggregates/aggregateWebHierarchy';

// 悪性通信1セット毎にリクエストとレスポンスでグループ化
const groupedPackets = groupPerMaliciousTraffic(pcapPackets, entranceSiteUrlList);

// 出力
fs.writeFile('results/grouped_packets.json', JSON.stringify(groupedPackets, null, 2), (err) => {
  if (err) throw err;
});

// ここから特徴量の集計（みなさんの好きな特徴量を計算します）
const featureValuesByMaliciousTraffic = [];

for (const groupedPacketPair of groupedPackets) {
  // WEB階層（ここでは，直列にリダイレクトした回数）
  const webHierarchy = aggregateWebHierarchy(groupedPacketPair);
  featureValuesByMaliciousTraffic.push({
    entranceUrl: groupedPacketPair.entranceUrl,
    webHierarchy,
  });
}

// 出力
fs.writeFile('results/feature_values.json', JSON.stringify(featureValuesByMaliciousTraffic, null, 2), (err) => {
  if (err) throw err;
});
