import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

class YourClass:
    NS = {"mpd": "urn:mpeg:dash:schema:mpd:2011"}

    def _expand_segment_timeline(self, seg_timeline_el) -> List[int]:
        """
        SegmentTimeline の <S> を展開して開始時刻（$Time$ に入る値）のリストを返す。
        仕様:
          - current_time は、<S> の t があればその値、無ければ直前からの加算。最初に無ければ 0。
          - 各 <S> は d(必須) と r(省略時0; 負値は次の t まで) を持つ。
          - r の意味は「追加で r 回」。合計は (r+1) 個。
          - r = -1 の場合、次の <S> の t まで d で刻んで埋める（次の t が無い場合はそこで打ち切り）。
        """
        # 先に <S> を配列化して next_t を参照できるようにする
        s_list = list(seg_timeline_el.findall("mpd:S", self.NS))
        times: List[int] = []
        current_time: Optional[int] = None

        for idx, s in enumerate(s_list):
            t_attr = s.get("t")
            d_attr = s.get("d")
            r_attr = s.get("r")

            if d_attr is None:
                raise ValueError("<S> に d がありません。")

            d = int(d_attr)
            r = int(r_attr) if r_attr is not None else 0

            # 次要素の t（r=-1の上限判定に使用）
            next_t: Optional[int] = None
            if idx + 1 < len(s_list):
                nt = s_list[idx + 1].get("t")
                if nt is not None:
                    next_t = int(nt)

            if t_attr is not None:
                current_time = int(t_attr)
            elif current_time is None:
                current_time = 0

            if r == -1:
                # 次の t まで d 間隔で埋める（次の t が無ければ 1 個だけ）
                if next_t is None:
                    # 仕様上 Period 長が分かればそこまでだが、ここでは 1 個だけ出す
                    times.append(current_time)
                    current_time += d
                else:
                    # current_time, current_time+d, ... < next_t となるように追加
                    while current_time < next_t:
                        times.append(current_time)
                        current_time += d
            else:
                # r >= 0: 合計 (r+1) 個
                repeat = r + 1
                for _ in range(repeat):
                    times.append(current_time)
                    current_time += d

        return times

    def get_segment_times_from_mpd(self, mpd_content: str) -> Optional[Dict[str, List[int]]]:
        """
        MPD(XML文字列)に SegmentTimeline が存在すれば、AdaptationSet 単位で
        タイムラインを展開して {contentType(or推定): [t0, t1, ...]} を返す。
        存在しなければ None。
        """
        try:
            root = ET.fromstring(mpd_content)
        except ET.ParseError as e:
            raise ValueError(f"MPDのXML解析に失敗しました: {e}")

        # すべての AdaptationSet を見て、SegmentTemplate/Timeline を探す
        results: Dict[str, List[int]] = {}
        found = False

        for adapt in root.findall(".//mpd:AdaptationSet", self.NS):
            # contentType があればそれをキーに、無ければ mimeType から推定
            ctype = adapt.get("contentType")
            if not ctype:
                mime = adapt.get("mimeType", "")
                if mime.startswith("audio"):
                    ctype = "audio"
                elif mime.startswith("video"):
                    ctype = "video"
                else:
                    # 連番の unknown キーを避けるため、id 等があれば使う
                    ctype = adapt.get("id", "unknown")

            # SegmentTemplate は AdaptationSet または Representation にありうる
            seg_tmpl = adapt.find("mpd:SegmentTemplate", self.NS)
            if seg_tmpl is None:
                # Representation 側をスキャン
                rep = adapt.find("mpd:Representation/mpd:SegmentTemplate", self.NS)
                seg_tmpl = rep

            if seg_tmpl is None:
                continue

            seg_timeline = seg_tmpl.find("mpd:SegmentTimeline", self.NS)
            if seg_timeline is None:
                continue

            # 見つかったら展開
            times = self._expand_segment_timeline(seg_timeline)
            results[ctype] = times
            found = True

        return results if found else None


mpd_str = open("e417f4c4-fdbb-4670-afef-d987fb6fd1af.xml", "r", encoding="utf-8").read()
obj = YourClass()

times_dict = obj.get_segment_times_from_mpd(mpd_str)
if times_dict is None:
    print("SegmentTimeline は存在しません。")
else:
    print(times_dict)