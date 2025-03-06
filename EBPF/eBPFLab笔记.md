# bpf lab笔记

```YAML
bpftool prog list
#可以查看当前挂载的eBPF程序
```

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=YjZiOWZkNDA3OTcwYTFiOWNhOTU4YjVmOTMwNzQ1ODJfM2dvdlhFdnhHT3M4bXpMMGxhV1dFNzRLT2cwTDBGQmpfVG9rZW46V3NDTGJIY0RIb2h4SkF4QWJoVGMxSFhsbkFPXzE3MjcwMDExMTA6MTcyNzAwNDcxMF9WNA)

```YAML
bpftool map list
#可以bpf程序关联的map，id对应上面命令中的map_ids
```

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=OGRjYjUwZDlhNWE4ZjE1NTJkZTA2NTAyY2U0MjQ0YTZfUTRJb3QzNFlIZHRVRmpBSnlCT3RXZUJ5d05iaGV1c21fVG9rZW46SUJLcGJ3blFNb2MwWDF4SUFZS2M2OGxKbkpkXzE3MjcwMDExMTA6MTcyNzAwNDcxMF9WNA)

```YAML
bpftool prog dump xlated id 46 linum
#可以查看某个eBPF程序的详细情况
```

![img](https://infracreate.feishu.cn/space/api/box/stream/download/asynccode/?code=ZGE1NDg2MzA5YTdhM2U1MWI1YzFjM2RjZTE1YzExNDZfQk5KM2s5RUR5SmpHMDdadzA1TWdacHRxSUNXOHI2R2VfVG9rZW46SjljVGJ0dHRDb0dRRG94bFBzWmN1RGhVbjBoXzE3MjcwMDExMTA6MTcyNzAwNDcxMF9WNA)