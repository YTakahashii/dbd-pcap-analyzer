import { GroupedMaliciousRequest } from 'src/models/GroupedMaliciousRequest';

// if文の中に 'application/...' などがあるととても読みにくいので，オブジェクトにまとめた
const ContentType = {
  PDF: 'application/pdf',
  SWF: 'application/x-shockwave-flash',
  JAR: 'application/java-archive',
  X_JAR: 'application/x-java-archive',
  BIN_OCTET_STREAM: 'application/octet-stream',
  BIN_X_MS_DOWNLOAD: 'application/x-msdownload',
  BIN_X_DOWNLOAD: 'application/x-download',
  BIN_X_MS_DOS_PROGRAM: 'application/x-msdos-program',
} as const;

export function aggregateDownloadFileType(groupedPacketPair: GroupedMaliciousRequest) {
  const downloadFileType = groupedPacketPair.responses.reduce(
    (fileType, response) => {
      const contentType = response._source?.layers?.http?.['http.content_type'];
      // 条件分岐が多岐にわたる場合は switch 文を使う
      switch (contentType) {
        case ContentType.PDF:
          fileType.pdf += 1;
          break;
        case ContentType.SWF:
          fileType.swf += 1;
          break;
        case ContentType.BIN_OCTET_STREAM:
        case ContentType.BIN_X_MS_DOWNLOAD:
        case ContentType.BIN_X_DOWNLOAD:
        case ContentType.BIN_X_MS_DOS_PROGRAM:
          fileType.bin += 1;
          break;
        case ContentType.JAR:
        case ContentType.X_JAR:
          fileType.jar += 1;
          break;
        default:
          break;
      }
      return fileType;
    },
    {
      // 反復処理関数の第1引数 fileType の初期値
      pdf: 0,
      swf: 0,
      bin: 0,
      jar: 0,
    }
  );

  return downloadFileType;
}
