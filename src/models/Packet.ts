// type PacketBase は 1パケット分のディスプレイフィルタをまとめたObjectの型
// type Packetはすべての属性をoptionalにした型．optionalというのは値があるかどうかわからないという意味．（パケットごとに入っている属性が違うため）
// 補完を効かせるためにすべてのディスプレイフィルタを含んでいる
// 足りないディスプレイフィルタがあれば追加して良い
// ディスプレイフィルタはここから確認できる https://www.wireshark.org/docs/dfref/
// 特に重要そうなHTTPのフィルタ: https://www.wireshark.org/docs/dfref/h/http.html
// 元のjsonファイルにおいて ip.addr などの一部の属性が同じObjectに重複している場合がある．そのような属性にはアクセスしない方が良い．（たくさんあるうちのどれか1つの値しか読み込めないため）

import { NestedPartial } from 'src/utils/NestedPartial';

type PacketBase = {
  _index: string;
  _type: string;
  _score: null;
  _source: {
    layers: {
      frame: {
        'frame.encap_type': string;
        'frame.time': string;
        'frame.offset_shift': string;
        'frame.time_epoch': string;
        'frame.time_delta': string;
        'frame.time_delta_displayed': string;
        'frame.time_relative': string;
        'frame.number': string;
        'frame.len': string;
        'frame.cap_len': string;
        'frame.marked': string;
        'frame.ignored': string;
        'frame.protocols': string;
        'frame.coloring_rule.name': string;
        'frame.coloring_rule.string': string;
      };
      eth: {
        'eth.dst': string;
        'eth.dst_tree': {
          'eth.dst_resolved': string;
          'eth.dst.oui': string;
          'eth.dst.oui_resolved': string;
          'eth.addr': string;
          'eth.addr_resolved': string;
          'eth.addr.oui': string;
          'eth.addr.oui_resolved': string;
          'eth.dst.lg': string;
          'eth.lg': string;
          'eth.dst.ig': string;
          'eth.ig': string;
        };
        'eth.src': string;
        'eth.src_tree': {
          'eth.src_resolved': string;
          'eth.src.oui': string;
          'eth.src.oui_resolved': string;
          'eth.addr': string;
          'eth.addr_resolved': string;
          'eth.addr.oui': string;
          'eth.addr.oui_resolved': string;
          'eth.src.lg': string;
          'eth.lg': string;
          'eth.src.ig': string;
          'eth.ig': string;
        };
        'eth.type': string;
      };
      ip: {
        'ip.version': string;
        'ip.hdr_len': string;
        'ip.tos': string;
        'ip.tos_tree': {
          'ip.tos.precedence': string;
          'ip.tos.delay': string;
          'ip.tos.throughput': string;
          'ip.tos.reliability': string;
          'ip.tos.cost': string;
        };
        'ip.len': string;
        'ip.id': string;
        'ip.flags': string;
        'ip.flags_tree': {
          'ip.flags.rb': string;
          'ip.flags.df': string;
          'ip.flags.mf': string;
        };
        'ip.frag_offset': string;
        'ip.ttl': string;
        'ip.proto': string;
        'ip.checksum': string;
        'ip.checksum.status': string;
        'ip.src': string;
        'ip.src_host': string;
        'ip.dst': string;
        'ip.dst_host': string;
        'ip.host': string;
      };
      tcp: {
        'tcp.srcport': string;
        'tcp.dstport': string;
        'tcp.port': string;
        'tcp.stream': string;
        'tcp.len': string;
        'tcp.seq': string;
        'tcp.seq_raw': string;
        'tcp.nxtseq': string;
        'tcp.ack': string;
        'tcp.ack_raw': string;
        'tcp.hdr_len': string;
        'tcp.flags': string;
        'tcp.flags_tree': {
          'tcp.flags.res': string;
          'tcp.flags.ns': string;
          'tcp.flags.cwr': string;
          'tcp.flags.ecn': string;
          'tcp.flags.urg': string;
          'tcp.flags.ack': string;
          'tcp.flags.push': string;
          'tcp.flags.reset': string;
          'tcp.flags.syn': string;
          'tcp.flags.fin': string;
          'tcp.flags.str': string;
        };
        'tcp.window_size_value': string;
        'tcp.window_size': string;
        'tcp.window_size_scalefactor': string;
        'tcp.checksum': string;
        'tcp.checksum.status': string;
        'tcp.urgent_pointer': string;
        'tcp.analysis': {
          'tcp.analysis.initial_rtt': string;
          'tcp.analysis.bytes_in_flight': string;
          'tcp.analysis.push_bytes_sent': string;
        };
        Timestamps: {
          'tcp.time_relative': string;
          'tcp.time_delta': string;
        };
        'tcp.payload': string;
      };
      http: {
        'http.accept': string;
        'http.accept_language': string;
        'http.user_agent': string;
        'http.host': string;
        'http.connection': string;
        'http.request.line': string;
        'http.request.full_uri': string;
        'http.request': string;
        'http.response': string;
        'http.request_number': string;
        'http.response_number': string;
        'http.response_in': string;
        'http.next_request_in': string;
        'http.next_response_in': string;
        'http.prev_response_in': string;
        'http.prev_request_in': string;
        'http.location': string;
        'http.referer': string;
        'http.response_for.uri': string;
        'http.content_type': string;
        'http.response.code': string;
        'HTTP/1.1 200 OK\\r\\n': {
          '_ws.expert': {
            'http.chat': string;
            '_ws.expert.message': string;
            '_ws.expert.severity': string;
            '_ws.expert.group': string;
          };
          'http.response.version': string;
          'http.response.code': string;
          'http.response.code.desc': string;
          'http.response.phrase': string;
        };
        'HTTP/1.1 302 Found\\r\\n': {
          '_ws.expert': {
            'http.chat': string;
            '_ws.expert.message': string;
            '_ws.expert.severity': string;
            '_ws.expert.group': string;
          };
          'http.response.version': string;
          'http.response.code': string;
          'http.response.code.desc': string;
          'http.response.phrase': string;
        };
        'HTTP/1.1 301 Moved Permanently\\r\\n': {
          '_ws.expert': {
            'http.chat': '';
            '_ws.expert.message': 'HTTP/1.1 301 Moved Permanently\\r\\n';
            '_ws.expert.severity': '2097152';
            '_ws.expert.group': '33554432';
          };
          'http.response.version': 'HTTP/1.1';
          'http.response.code': '301';
          'http.response.code.desc': 'Moved Permanently';
          'http.response.phrase': 'Moved Permanently';
        };
      };
    };
  };
};

export type Packet = NestedPartial<PacketBase>;
