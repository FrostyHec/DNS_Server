


def shorten_ipv6(ipv6: str) -> str:
    # implement a function to convert the ipv6 address to a shorter version
    arr = ipv6.split(':')
    zero_len, seg_idx, max_zero_len, max_zero_seg_idx = 0, -1, 0, -1
    for i in range(len(arr)):
        if arr[i] == '0':
            if seg_idx == -1:
                seg_idx = i
            zero_len += 1
            if zero_len > max_zero_len:
                max_zero_len = zero_len
                max_zero_seg_idx = seg_idx
        else:
            zero_len = 0
            seg_idx = -1
    if max_zero_len == 0:
        return ipv6
    res = ""
    seg_used=False
    for i in range(len(arr)):
        if i < max_zero_seg_idx or i >= max_zero_seg_idx + max_zero_len:  # 不需要过滤
            res += arr[i]
            res += ":"
        else:
            if not seg_used:
                if max_zero_seg_idx==0 or max_zero_seg_idx + max_zero_len==len(arr):
                    res+="::"
                else:
                    res+=":"
                seg_used=True
    if max_zero_len==8:
        return '::'
    return res[:-1]

# 0:0:2:0:2:3:4:5 -> ::2:0:2:3:4:5,2:0:0:0:2:3:4:5
