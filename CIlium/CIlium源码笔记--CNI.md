# Cilium源码--CNI

![img](https://arthurchiao.art/assets/img/cilium-code-cni/client-scaleup-cnp.png)

Cilium CNI插件主要执行以下步骤：

1. 创建链路设备（Veth、IPVLAN）
2. 分配IP地址
3. 配置Pod网络，例如IP地址、路由表、sysctl参数
4. 通过Cilium Agent API创建本地节点的端点（Endpoint）
5. 通过Kubernetes API创建CiliumEndpoint（CRD）
6. 通过KVStore检索或者为当前端点分配身份标识
7. 计算网络策略
8. 将IP信息（例如IP到身份标识的映射）保存到KVStore
9. 生成、编译、并将BPF代码注入内核

## 0.1 Source code tree

1. `api/` - cilium REST API entrypoints
2. `daemon/cmd/` - cilium daemon (agent) implementation, including:
   1. IPAM API handler implementation
   2. endpoint API handler
   3. others
3. `plugin/` - plugin implementations for CNI, docker, etc
4. `pkg/` - cilium core functionalities implementation

## 0.2 Add Network Skeleton Code

当kubelet调用plugin来为一个Pod添加网络，cmd.Add()会被调用

```
func (cmd *Cmd) Add(args *skel.CmdArgs) (err error) {
    n, err := types.LoadNetConf(args.StdinData)
    niTypes.LoadArgs(args.Args, cniArgs)
    conf, err := getConfigFromCiliumAgent(c)
    
    configs, err := cmd.cfg.GetConfigurations(ConfigurationParams{log, conf, args, cniArgs})
    ns, err := netns.OpenPinned(args.Netns)
    
    for _, epConf := range configs {
    		state, ep, err := epConf.PrepareEndpoint(ipam)
    		
    		switch conf.DatapathMode {
				case datapathOption.DatapathModeVeth:
						veth, peer, tmpIfName, err := connector.SetupVeth(cniID, 				int(conf.DeviceMTU),
								int(conf.GROMaxSize), int(conf.GSOMaxSize),
								int(conf.GROIPV4MaxSize), int(conf.GSOIPV4MaxSize), ep, sysctl)
						 netlink.LinkSetNsFd(peer, ns.FD())
						 err = connector.SetupVethRemoteNs(ns, tmpIfName, epConf.IfName())
				case ......
				
				if ipv6IsEnabled(ipam) && conf.Addressing.IPV6 != nil {}
				if ipv4IsEnabled(ipam) && conf.Addressing.IPV4 != nil {
						ipConfig, routes, err = prepareIP(ep.Addressing.IPV4, state, int(conf.RouteMTU))
						res.IPs = append(res.IPs, ipConfig)
						res.Routes = append(res.Routes, routes...)
				}
				switch conf.IpamMode {
				case ipamOption.IPAMENI, ipamOption.IPAMAzure, 		ipamOption.IPAMAlibabaCloud:
						err = interfaceAdd(ipConfig, ipam.IPV4, conf)

				}
				ns.Do(func() error {
						macAddrStr, err = configureIface(ipam, epConf.IfName(), state)
				}
				
				newEp, err = c.EndpointCreate(ep);
    }
    return cniTypes.PrintResult(res, n.CNIVersion)
    
}
```

# 1 Create link device

kubelet在发送创建Pod网络的请求时，会向CNI plugin传递CmdArgs类型的变量（github.com/containernetworking/cni/pkg/skel）

```
// CmdArgs captures all the arguments passed in to the plugin via both env vars and stdin
type CmdArgs struct {
        ContainerID string // container ID
        Netns       string // container netns
        IfName      string // desired interface name for container, e.g. `eth0`
        Args        string // Platform-specific parameters of the container, e.g.
                           // `K8S_POD_NAMESPACE=xx;K8S_POD_NAME=xx;K8S_POD_INFRA_CONTAINER_ID=xx`
        Path        string // Path for locating CNI plugin binary, e.g. `/opt/cni/bin`
        StdinData   []byte // Network configurations
}
```

`StdinData`字段将被反序列化为`netConf`变量

```
// NetConf describes a network.
type NetConf struct {
    CNIVersion string `json:"cniVersion,omitempty"`

    Name         string          `json:"name,omitempty"`
    Type         string          `json:"type,omitempty"`
    Capabilities map[string]bool `json:"capabilities,omitempty"`
    IPAM         IPAM            `json:"ipam,omitempty"`
    DNS          DNS             `json:"dns"`

    RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
    PrevResult    Result                 `json:"-"`
}
```

在解析这些网络配置后，Plugin会为该Pod创建一个网络设备

## 1.2 Create veth pair

在Cilium中，连接容器和主机的虚拟设备被称为”connector“

CNI plugin首先调用connector.SetupVeth()来创建一个veth对，并将容器ID、MTU和端点信息作为参数传入

```
veth, peer, tmpIfName, err := connector.SetupVeth(cniID, int(conf.DeviceMTU),
```

**veth对设备的命名规则：**

- 主机端：`lxc` + 容器ID的sha256哈希值的前N位，例如`lxc12c45`
- 对端（容器端）：`tmp` + 容器ID的sha256哈希值的前N位，例如`tmp12c45`

**连接器中的额外步骤（位于`pkg/endpoint/connector/veth.go`）：**

1. 设置系统参数：`/proc/sys/net/ipv4/conf/<veth>/rp_filter = 0`
2. 设置MTU
3. 填充端点信息：容器的MAC地址、主机端MAC地址、接口名称、接口索引

## 1.3 Move peer to container netns

之后，CNI plugin会将通过将对端的veth设备的网络命名空间设置为容器的netns，将其放入容器中

```
netlink.LinkSetNsFd(*peer, int(netNs.Fd()))
```

这样，对端设备会从主机上“消失”，即在主机上执行`ifconfig`或`ip link`命令时不会显示该设备。你必须指定网络命名空间才能看到它：

## 1.4 Rename peer

CNI插件将对端设备重命名为CNI参数中指定的名称：

```
connector.SetupVethRemoteNs(netNs, tmpIfName, args.IfName)
```

例如，这会将容器内的`tmp53057`重命名为`eth0`。这正是每个容器中`eth0`设备诞生的过程。

# 2 Allocate IP address

接下来，plugin会尝试从IPAM（IP地址管理）中分配IP地址（包括IPv4和IPv6），而IPAM是嵌入在本地的Cilium agent中的。

Cilium agent是一个在每个主机上运行的守护进程，它内部包含了许多服务，例如本地的IPAM、端点管理器等。这些服务通过REST API对外提供服务。

IP分配的过程远比表面看起来复杂。代码虽然只有一行：

```
ipam := c.IPAMAllocate("")
```

但其调用栈会跳转到多个不同的地方：

1. **插件** - `plugin/cilium-cni/`
2. **Cilium客户端** - `pkg/client/`
3. **Cilium REST API** - `api/v1/server/restapi/ipam/`
4. **Cilium API服务器** - `api/v1/server/restapi/ipam`
5. **实际的HTTP处理函数** - `daemon/cmd/ipam.go`
6. **Cilium IPAM实现（实际上只是一个封装）** - `pkg/ipam/`
7. **最终的IPAM实现（Kubernetes内置）** - `k8s.io/kubernetes/pkg/registry/core/service/ipallocator`

## 2.1 Allocate IP address for given Pod

首先从client.IPAMAllocate开始

```
podName := string(cniArgs.K8S_POD_NAMESPACE) + "/" + string(cniArgs.K8S_POD_NAME)
ipam, err := client.IPAMAllocate("", podName, ipamPoolName, true)
```

## 2.2 Cilium client: `IPAMAllocate()`

`IPAMAllocate()`地址族和所有者；如果地址族为空，则会同时分配一个IPv4和一个IPv6地址。这些地址会分别存储在以下字段中：

- `ipam.Address.IPV4`
- `ipam.Address.IPV6`

```
// IPAMAllocate allocates an IP address out of address family specific pool.
func (c *Client) IPAMAllocate(family, owner string) (*models.IPAMResponse, error) {
    params := ipam.NewPostIPAMParams().WithTimeout(api.ClientTimeout)

    if family != ""
        params.SetFamily(&family)
    if owner != ""
        params.SetOwner(&owner)

    resp, err := c.IPAM.PostIPAM(params)
    return resp.Payload, nil
}
```

client的结构体定义在pkt/client/client.go

```
type Client struct {
    clientapi.Cilium
}
```

the client API `clientapi.Cilium` is further defined in `api/v1/client/cilium_client.go`:

```
// clientapi
type Cilium struct {
    Daemon *daemon.Client

    Endpoint *endpoint.Client
    IPAM *ipam.Client              // implemented in "api/v1/client/ipam"
    Metrics *metrics.Client
    Policy *policy.Client
    Prefilter *prefilter.Client
    Service *service.Client
    Transport runtime.ClientTransport
}
```

## 2.3 Call REST API: allocate IP

The cilium API code is auto-generated with golang OpenAPI tools.

```
func (a *Client) PostIpam(params *PostIpamParams, opts ...ClientOption) (*PostIpamCreated, error) {
		result, err := a.transport.Submit(op)
		success, ok := result.(*PostIpamCreated)
}
```

## 2.4 IPAM API server

HTTP的接受端在api/v1/server/restapi/ipam/post_ipam.go

```
func (o *PostIpam) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
       *r = *rCtx
    }
    var Params = NewPostIpamParams()
    if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
       o.Context.Respond(rw, r, route.Produces, route, err)
       return
    }

    res := o.Handler.Handle(Params) // actually handle the request
    o.Context.Respond(rw, r, route.Produces, route, res)

}
```

## 2.5 IPAM HTTP handler

```
func (r *IpamPostIpamHandler) Handle(params ipamapi.PostIpamParams) middleware.Responder {
		resp := &models.IPAMResponse{
				HostAddressing: node.GetNodeAddressing(),
				Address:        &models.AddressPair{},
		}
		
		ipv4Result, ipv6Result, err := r.IPAM.AllocateNextWithExpiration(family, owner, pool, expirationTimeout)
		
		if ipv4Result != nil {
		resp.Address.IPV4 = ipv4Result.IP.String()
		resp.Address.IPV4PoolName = ipv4Result.IPPoolName.String()
		resp.IPV4 = &models.IPAMAddressResponse{
			Cidrs:           ipv4Result.CIDRs,
			IP:              ipv4Result.IP.String(),
			MasterMac:       ipv4Result.PrimaryMAC,
			Gateway:         ipv4Result.GatewayIP,
			ExpirationUUID:  ipv4Result.ExpirationUUID,
			InterfaceNumber: ipv4Result.InterfaceNumber,
			}
		}
		
		return ipamapi.NewPostIpamCreated().WithPayload(resp)
}
```

`h.daemon.ipam`实际上是一个CIDR（无类别域间路由），它在`pkg/ipam/ipam.go`中被初始化。

```
// NewIPAM returns a new IP address manager
func NewIPAM(nodeAddressing datapath.NodeAddressing, c Configuration) *IPAM {
    ipam := &IPAM{
        nodeAddressing: nodeAddressing,
        config:         c,
    }

    if c.EnableIPv4
        ipam.IPv4Allocator = ipallocator.NewCIDRRange(nodeAddressing.IPv4().AllocationCIDR().IPNet)

    return ipam
}
```

正如我们所看到的，它从指定的CIDR中分配IP地址。

这里需要注意一个重要的事情：这是一个内存中的IPAM（IP地址管理）——也就是说，它的所有状态（例如已分配的IP、可用的IP、保留的IP）都存储在内存中，因此在服务重启时不会保留。

如果IPAM状态存储在内存中，那么Cilium代理如何在重启时恢复状态呢？

答案是：Cilium代理会将每个分配的IP地址记录在本地文件中，更具体地说，是记录在每个端点的BPF头文件中。我们稍后会看到这一点。

接下来，我们继续深入，进入`h.daemon.ipam.AllocateNext(params.Family)`的逻辑。

## 2.6 IPAM implementation in `pkg/ipam`

```
func (ipam *IPAM) AllocateNextWithExpiration(family, owner string, pool Pool, timeout time.Duration) (ipv4Result, ipv6Result *AllocationResult, err error) {
		ipv4Result, ipv6Result, err = ipam.AllocateNext(family, owner, pool)
		
		for _, result := range []*AllocationResult{ipv4Result, ipv6Result} {
				result.ExpirationUUID, err = ipam.StartExpirationTimer(result.IP, result.IPPoolName, timeout)
				if err != nil {
            if ipv4Result != nil {
                ipam.ReleaseIP(ipv4Result.IP, ipv4Result.IPPoolName)
            }
        }
		}
}
```

```
// AllocateNext allocates the next available IPv4 and IPv6 address out of the
// configured address pool. If family is set to "ipv4" or "ipv6", then
// allocation is limited to the specified address family. If the pool has been
// drained of addresses, an error will be returned.
func (ipam *IPAM) AllocateNext(family, owner string, pool Pool) (ipv4Result, ipv6Result *AllocationResult, err error) {
		ipv4Result, err = ipam.AllocateNextFamily(IPv4, owner, pool)
		if err != nil {
			if ipv6Result != nil {
				ipam.ReleaseIP(ipv6Result.IP, ipv6Result.IPPoolName)
			}
			return
		}
}
```

```go
// AllocateNextFamily allocates the next IP of the requested address family
func (ipam *IPAM) AllocateNextFamily(family Family, owner string, pool Pool) (result *AllocationResult, err error) {
    ipam.allocatorMutex.Lock()
    defer ipam.allocatorMutex.Unlock()

    needSyncUpstream := true

    return ipam.allocateNextFamily(family, owner, pool, needSyncUpstream)
}


func (ipam *IPAM) allocateNextFamily(family Family, owner string, pool Pool, needSyncUpstream bool) (result *AllocationResult, err error) {
		for {
				
      	ipam.registerIPOwner(result.IP, owner, pool)
		}
}
```

## 2.7 Real allocation logic in K8s builtin IPAM

这一部分涉及到K8s的处理逻辑，即从IP池中预留IP地址。

```
// AllocateNext reserves one of the IPs from the pool. ErrFull may
// be returned if there are no addresses left.
func (r *Range) AllocateNext() (net.IP, error) {
	offset, ok, err := r.alloc.AllocateNext()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrFull
	}
	return addIPOffset(r.base, offset), nil
}
```

r.alloc是接口

```
// Interface manages the allocation of items out of a range. Interface
// should be threadsafe.
type Interface interface {
    Allocate(int) (bool, error)
    AllocateNext() (int, bool, error)
    Release(int)
    ForEach(func(int))
    Has(int) bool
    Free() int
}
```

`r.alloc.AllocateNext()` 返回的是下一个可用IP相对于该CIDR中第一个IP（即`r.base`）的偏移量，而`addIPOffset()`则将此偏移量转换为`net.IP`格式的表示。

```
// AllocateNext reserves one of the items from the pool.
// (0, false, nil) may be returned if there are no items left.
func (r *AllocationBitmap) AllocateNext() (int, bool, error) {
    r.lock.Lock()
    defer r.lock.Unlock()

    next, ok := r.strategy.AllocateBit(r.allocated, r.max, r.count)
    if !ok {
       return 0, false, nil
    }
    r.count++
    r.allocated = r.allocated.SetBit(r.allocated, next, 1)
    return next, true, nil
}
```

```
func (rss randomScanStrategy) AllocateBit(allocated *big.Int, max, count int) (int, bool) {
    if count >= max {
       return 0, false
    }
    offset := rand.IntN(max)
    for i := 0; i < max; i++ {
       at := (offset + i) % max
       if allocated.Bit(at) == 0 {
          return at, true
       }
    }
    return 0, false
}

func (contiguousScanStrategy) AllocateBit(allocated *big.Int, max, count int) (int, bool) {
	if count >= max {
		return 0, false
	}
	for i := 0; i < max; i++ {
		if allocated.Bit(i) == 0 {
			return i, true
		}
	}
	return 0, false
}
```

IP地址管理（IPAM）的实现非常简洁。它通过维护一个位图来进行IP地址的分配：当一个IP地址从池中被分配出去时，相应的位会被置为1；当IP地址返回到池中时，该位则被重置为0。通过这种方式，IPAM能够高效地管理IP地址池。

此外，IPAM还支持不同的分配策略，正如代码片段所示，例如顺序分配或随机分配。这样的设计使得IPAM能够灵活应对各种分配需求。

# 3 Configure pod network

IP地址的准备工作已经完成。接下来的步骤如下：

1. 计算路由和网关
2. 配置IP地址、路由、网关、`sysctl`参数等

这些步骤将确保网络功能的完整性和高效性。

```
if ipv4IsEnabled(ipam) && conf.Addressing.IPV4 != nil {
    ep.Addressing.IPV4 = ipam.Address.IPV4
    ep.Addressing.IPV4PoolName = ipam.Address.IPV4PoolName
    ep.Addressing.IPV4ExpirationUUID = ipam.IPV4.ExpirationUUID

    ipConfig, routes, err = prepareIP(ep.Addressing.IPV4, state, int(conf.RouteMTU))
    if err != nil {
       return fmt.Errorf("unable to prepare IP addressing for %s: %w", ep.Addressing.IPV4, err)
    }
    // set the addresses interface index to that of the container-side interface
    ipConfig.Interface = cniTypesV1.Int(len(res.Interfaces))
    res.IPs = append(res.IPs, ipConfig)
    res.Routes = append(res.Routes, routes...)
}
```

## 3.1 Prepare IP addresses, routes, gateway

`prepareIP()` 函数会准备IP地址、网关、路由条目等。该函数将返回一个指向 `IPConfig` 的指针，其中包含IP和网关信息，以及一个路由条目列表。

```
func prepareIP(ipAddr string, state *CmdState, mtu int) (*cniTypesV1.IPConfig, []*cniTypes.Route, error) {
    // This handles both scenarios for handling IPaddress as CIDR as well as IPaddress
    // from delegated Ipam and cilium-agent
    ipPrefix, err := netip.ParsePrefix(ipAddr)
    if err != nil {
      ip, err = netip.ParseAddr(ipAddr)
    } else {
      ip = ipPrefix.Addr()
    }


		state.IP4 = ip
		if state.HostAddr != nil {
			if routes, err = connector.IPv4Routes(state.HostAddr, mtu); err != nil {
				return nil, nil, err
			}
			state.IP4routes = append(state.IP4routes, routes...)
			gw = connector.IPv4Gateway(state.HostAddr)
		}
		
		gwIP = net.ParseIP(gw)
		return &cniTypesV1.IPConfig{
      Address: *iputil.AddrToIPNet(ip),
      Gateway: gwIP,
    }, rt, nil
}
```

IP通过netip.ParsePrefix()或者netip.ParseAddr进行转换

#### Routes

IPv4Routes() 会返回IPv4 routes ，该路由需要在终端的网络命名空间中安装

```
// IPv4Routes returns IPv4 routes to be installed in endpoint's networking namespace.
func IPv4Routes(addr *models.NodeAddressing, linkMTU int) ([]route.Route, error) {
    ip := net.ParseIP(addr.IPV4.IP)
    return []route.Route{
       {
          Prefix: net.IPNet{
             IP:   ip,
             Mask: defaults.ContainerIPv4Mask,
          },
       },
       {
          Prefix:  defaults.IPv4DefaultRoute,
          Nexthop: &ip,
          MTU:     linkMTU,
       },
    }, nil
}
```

#### Gateway

网关仅设置为主机的 IP 地址

```
// IPv4Gateway returns the IPv4 gateway address for endpoints.
func IPv4Gateway(addr *models.NodeAddressing) string {
    // The host's IP is the gateway address
    return addr.IPV4.IP
}
```

## 3.2 Configure interface

在网络信息准备就绪之后，下一步是将它们配置到容器中。这是通过调用 `configureIface` 函数来实现的。

```
func configureIface(ipam *models.IPAMResponse, ifName string, state *CmdState) (string, error) {
		l, err := safenetlink.LinkByName(ifName)
		netlink.LinkSetUp(l)
		
		addIPConfigToLink(state.IP4, state.IP4routes, state.IP4rules, l, ifName)
		
}
```

首先会通过LinkByName通过设备名称（容器内的 eth0）找到链路设备，然后调用 `addIPConfigToLink` 来执行实际的操作

```
func addIPConfigToLink(ip netip.Addr, routes []route.Route, rules []route.Rule, link netlink.Link, ifName string) error {
		addr := &netlink.Addr{IPNet: iputil.AddrToIPNet(ip)}
		netlink.AddrAdd(link, addr)
		
		// Sort provided routes to make sure we apply any more specific
		// routes first which may be used as nexthops in wider routes
		sort.Sort(route.ByMask(routes))
		
		for _, r := range routes {
				rt := &netlink.Route{
          LinkIndex: link.Attrs().Index,
          Scope:     netlink.SCOPE_UNIVERSE,
          Dst:       &r.Prefix,
          MTU:       r.MTU,
          Table:     r.Table,
        }

        if r.Nexthop == nil {
          rt.Scope = netlink.SCOPE_LINK
        } else {
          rt.Gw = *r.Nexthop
        }
        netlink.RouteAdd(rt);
		}
}
```

1. 首先调用 `netlink.AddrAdd` 将 IP 地址添加到设备上，
2. 然后使用 `netlink.RouteAdd` 安装路由条目。

# 4 Create endpoint

端点是“一个带有命名空间的网络接口，Cilium 会对其应用策略”。最简单地说，每个普通的 Pod 都对应一个 Cilium 端点。

端点是节点本地的概念，也就是说，每个节点上的端点 ID 是重叠的。

端点的信息实际上也存储在本地文件中（再次强调，是 BPF 头文件），因此 Cilium 代理可以在重启时恢复它们。

```
// Endpoint An endpoint is a namespaced network interface to which cilium applies policies
//
// swagger:model Endpoint
type Endpoint struct {

    // The cilium-agent-local ID of the endpoint
    ID int64 `json:"id,omitempty"`

    // The desired configuration state of the endpoint
    Spec *EndpointConfigurationSpec `json:"spec,omitempty"`

    // The desired and realized configuration state of the endpoint
    Status *EndpointStatus `json:"status,omitempty"`
}
```

## 4.1 CNI: create Endpoint

```
// EndpointCreate creates a new endpoint
func (c *Client) EndpointCreate(ep *models.EndpointChangeRequest) (*models.Endpoint, error) {
    id := pkgEndpointID.NewCiliumID(ep.ID)
    params := endpoint.NewPutEndpointIDParams().WithID(id).WithEndpoint(ep).WithTimeout(api.ClientTimeout)
    resp, err := c.Endpoint.PutEndpointID(params)
    if err != nil {
       return nil, Hint(err)
    }
    return resp.Payload, nil
}
```

首先调用NewCiliumID()来生成本地端点标识

```
// NewCiliumID returns a new endpoint identifier of type CiliumLocalIdPrefix
func NewCiliumID(id int64) string {
    return NewID(CiliumLocalIdPrefix, strconv.FormatInt(id, 10))
}
```

正如注释所说，这个 ID 是主机本地的，这意味着它在主机范围内是唯一的。

然后，客户端代码会组织请求数据，并通过 `PutEndpointID(params)` 将这些数据通过 Cilium 的 REST API 进行 PUT 请求。

```
func (a *Client) PutEndpointID(params *PutEndpointIDParams, opts ...ClientOption) (*PutEndpointIDCreated, error) {
		result, err := a.transport.Submit(op)
}
```

## 4.3 Cilium HTTP server: create Endpoint

API Server 位于Daemonset中

```
func (o *PutEndpointID) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
       *r = *rCtx
    }
    var Params = NewPutEndpointIDParams()
    if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
       o.Context.Respond(rw, r, route.Produces, route, err)
       return
    }

    res := o.Handler.Handle(Params) // actually handle the request
    o.Context.Respond(rw, r, route.Produces, route, res)

}
```

收到HTTP请求后会调用`o.Handler.Handle()`.

## 4.4 HTTP Handler: create endpoint

HTTP Handler 在 api/v1/server/restapi/endpoint/put_endpoint_id.go

```
/*
    PutEndpointID swagger:route PUT /endpoint/{id} endpoint putEndpointId

# Create endpoint

Creates a new endpoint
*/
type PutEndpointID struct {
    Context *middleware.Context
    Handler PutEndpointIDHandler
}

func (o *PutEndpointID) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
       *r = *rCtx
    }
    var Params = NewPutEndpointIDParams()
    if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
       o.Context.Respond(rw, r, route.Produces, route, err)
       return
    }

    res := o.Handler.Handle(Params) // actually handle the request
    o.Context.Respond(rw, r, route.Produces, route, res)

}
```



```
// PutEndpointIDHandlerFunc turns a function with the right signature into a put endpoint ID handler
type PutEndpointIDHandlerFunc func(PutEndpointIDParams) middleware.Responder

// Handle executing the request and returning a response
func (fn PutEndpointIDHandlerFunc) Handle(params PutEndpointIDParams) middleware.Responder {
    return fn(params)
}
```

```
out.EndpointPutEndpointIDHandler = wrapAPIHandler(dp, putEndpointIDHandler)
```

```
func putEndpointIDHandler(d *Daemon, params PutEndpointIDParams) (resp middleware.Responder) {
		ep, code, err := d.createEndpoint(params.HTTPRequest.Context(), d, epTemplate)
}
```

最终会调用到createEndpoint（），此方法尝试创建与指定变更请求对应的端点（endpoint）。

```
func (d *Daemon) createEndpoint() {
		// We don't need to create the endpoint with the labels. This might cause
    // the endpoint regeneration to not be triggered further down, with the
    // ep.UpdateLabels or the ep.RunMetadataResolver, because the regeneration
    // is only triggered in case the labels are changed, which they might not
    // change because NewEndpointFromChangeModel would contain the
    // epTemplate.Labels, the same labels we would be calling ep.UpdateLabels or
    // the ep.RunMetadataResolver.
    apiLabels := labels.NewLabelsFromModel(epTemplate.Labels)
    
    ep, err := endpoint.NewEndpointFromChangeModel(d.ctx, owner, d, d.ipcache, d.l7Proxy, d.identityAllocator, epTemplate)
    oldEp := d.endpointManager.LookupCiliumID(ep.ID)
    oldEp = d.endpointManager.LookupCNIAttachmentID(ep.GetCNIAttachmentID())
    
    d.endpointCreations.NewCreateRequest(ep, cancel)
		defer d.endpointCreations.EndCreateRequest(ep)
		
		pod, k8sMetadata, err := d.handleOutdatedPodInformer(ctx, ep)
		
		identityLbls.MergeLabels(k8sMetadata.IdentityLabels)
    infoLabels.MergeLabels(k8sMetadata.InfoLabels)
    
    err = d.endpointManager.AddEndpoint(owner, ep)
    
    if ep.K8sNamespaceAndPodNameIsSet() && d.clientset.IsEnabled() {
		// We need to refetch the pod labels again because we have just added
		// the endpoint into the endpoint manager. If we have received any pod
		// events, more specifically any events that modified the pod labels,
		// between the time the pod was created and the time it was added
		// into the endpoint manager, the pod event would not have been processed
		// since the pod event handler would not find the endpoint for that pod
		// in the endpoint manager. Thus, we will fetch the labels again
		// and update the endpoint with these labels.
		// Wait for the regeneration to be triggered before continuing.
		regenTriggered = ep.RunMetadataResolver(false, true, apiLabels, d.bwManager, d.fetchK8sMetadataForEndpoint)
	} else {
		regenTriggered = ep.UpdateLabels(ctx, labels.LabelSourceAny, identityLbls, infoLabels, true)
	}
		if build {
			ep.Regenerate(regenMetadata)
		}
}
```

`endpointmanager.AddEndpoint()` 会进一步调用 `ep.Expose()` 通知 notifier，后者将为此端点启动一个控制器，用于将该端点的信息同步到 API 服务器，作为对应的 CiliumEndpoint

随后，它调用 `ep.UpdateLabels()`，这可能会：

1. 尝试获取此端点的身份（identity）：例如，在扩展现有的 StatefulSet 时，身份在 Pod 创建之前已经存在。
2. 为此端点分配身份：例如，在创建新的 StatefulSet 时。
   我们将在第 6 节中看到这一点。

最后，它通过调用 `ep.Regenerate()` 并传入原因“Initial build on endpoint creation”来触发 BPF 代码的重新生成。如果成功，revision号将变为正数

# 5 Create CiliumEndpoint (CEP)

```
func (mgr *endpointManager) expose(ep *endpoint.Endpoint) error {
    newID, err := mgr.allocateID(ep.ID)
    if err != nil {
       return err
    }

    mgr.mutex.Lock()
    // Get a copy of the identifiers before exposing the endpoint
    identifiers := ep.Identifiers()
    ep.PolicyMapPressureUpdater = mgr.policyMapPressure
    ep.Start(newID)
    mgr.mcastManager.AddAddress(ep.IPv6)
    mgr.updateIDReferenceLocked(ep)
    mgr.updateReferencesLocked(ep, identifiers)
    mgr.mutex.Unlock()

    ep.InitEndpointHealth(mgr.health)
    mgr.RunK8sCiliumEndpointSync(ep, ep.GetReporter("cep-k8s-sync"))

    return nil
}
```

RunK8sCiliumEndpointSync 启动一个控制器，用于将端点同步到对应的 Kubernetes CiliumEndpoint CRD
预期每个 CEP 都有一个控制器负责更新它，并且会保留一个本地副本，仅推送更新。
CiliumEndpoint 对象与它们所代表的 Pod 具有相同的名称。

```
func (epSync *EndpointSynchronizer) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, h cell.Health) {
		ciliumClient := epSync.Clientset.CiliumV2()
		
		e.UpdateController(controllerName,
				controller.ControllerParams{
						DoFunc: 
								if firstTry {
                  // First we try getting CEP from the API server cache, as it's cheaper.
                  // If it fails we get it from etcd to be sure to have fresh data.
                  localCEP, err = ciliumClient.CiliumEndpoints(cepOwner.GetNamespace()).Get(ctx, cepName, meta_v1.GetOptions{ResourceVersion: "0"})
                  firstTry = false
                } else {
                  localCEP, err = ciliumClient.CiliumEndpoints(cepOwner.GetNamespace()).Get(ctx, cepName, meta_v1.GetOptions{})
                }
                case k8serrors.IsNotFound(err):
                		localCEP, err = ciliumClient.CiliumEndpoints(cepOwner.GetNamespace()).Create(ctx, cep, meta_v1.CreateOptions{})
                if localCEP == nil {
                  localCEP, err = ciliumClient.CiliumEndpoints(cepOwner.GetNamespace()).Get(ctx, cepName, meta_v1.GetOptions{})
}
```

# 6 Retrieve or allocate identity

“身份（Identity）”是一个集群范围的概念（相比之下，“端点（Endpoint）”是一个节点范围的概念），这意味着它在整个 Kubernetes 集群中是唯一的。

因此，为了确保身份在整个集群中唯一，它们由集群中的一个中心组件分配——没错，就是键值存储（kvstore，例如 cilium-etcd）。

从 `ep.UpdateLabels()` 开始：

UpdateLabels 被调用以更新给定 `sourceFilter` 的端点标签，如果 `source` 是 `LabelSourceAny`，则所有标签都会被替换。对此函数的调用并不意味着标签实际发生了改变。容器运行时会定期同步标签。指定的 `sourceFilter` 只会移除具有相同源的标签。例如，如果端点包含 `k8s:foo=bar`，并且 `sourceFilter` 是 `cni`，且带有标签 `cni:bar=bar`，则结果为 `k8s:foo=bar` + `cni:bar=bar`，即 "foo=bar" 标签被保留；如果 `sourceFilter` 是 `any`，且带有标签 `cni:bar=bar`，则结果为 `cni:bar=bar`，即 "foo=bar" 标签被移除。如果网络标签发生更改，端点将获得新的安全身份并重新生成。如果 `blocking` 为 true，则这两个操作将首先同步运行，然后在后台运行。如果触发了端点重新生成，则返回 `true`。

```
func (e *Endpoint) UpdateLabels(ctx context.Context, sourceFilter string, identityLabels, infoLabels labels.Labels, blocking bool) (regenTriggered bool) {
		e.replaceInformationLabels(sourceFilter, infoLabels)
		rev := e.replaceIdentityLabels(sourceFilter, identityLabels)
}
```

调用栈：

```
         |-ep.UpdateLabels                      // pkg/endpoint/endpoint.go
         |  |-replaceInformationLabels          // pkg/endpoint/endpoint.go
         |  |-ReplaceIdentityLabels             // pkg/endpoint/endpoint.go
         |     |-RunIdentityResolver            // pkg/endpoint/endpoint.go
         |        |-identityLabelsChanged       // pkg/endpoint/endpoint.go
         |           |-AllocateIdentity         // kvstore: reuse existing or create new one
         |           |-forcePolicyComputation
         |           |-SetIdentity
         |              |-runIPIdentitySync     // pkg/endpoint/policy.go
         |                 |-UpsertIPToKVStore  // pkg/ipcache/kvstore.go
```

在确定该端点的身份后，Cilium 代理会执行两项重要操作：

首先，重新计算网络策略，因为身份是最终的安全标识。我们将在第 7 节中详细讨论这一点。

其次，通过调用 `UpsertIPToKVStore()` 将 IP -> 身份的映射插入键值存储（kvstore）中。这对于 Cilium 网络策略框架至关重要。我们将在第 8 节中深入探讨这一点。

# 7 Calculate Policy

在身份确定后，将调用 `forcePolicyComputation()` 来计算该端点的网络策略，例如哪些服务可以访问该端口的哪些端口。

# 8 Upsert IP information to kvstore

![img](https://arthurchiao.art/assets/img/cilium-code-cni/client-scaleup-cnp.png)

举个例子，当从这个端点（Pod）发出的数据包到达另一个节点上的Pod时，它们会通过数据包的身份来决定是否允许这次通信。那么，Cilium如何确定这个数据包的身份呢？在直接路由的情况下，Cilium会执行以下操作：

1. 监听键值存储（kvstore）中的IP到身份映射（cilium/state/ip/v1），并将其保存到本地缓存（ipcache）中。
2. 从数据包中提取源IP地址（src_ip），并以该源IP地址为哈希键在本地缓存中查找身份信息。

# 9 Re-generate BPF code

典型的工作流程 [3]：

1. 生成eBPF源代码（使用C语言的一个子集）。
2. 使用LLVM将其编译为ELF文件，该文件包含程序代码、映射规范以及相关的重定位数据。
3. 解析ELF内容，并通过诸如tc（流量控制）等工具将程序加载到内核中。

在eBPF中，映射（maps）是内核中高效的键值存储，不仅可以在各种eBPF程序之间共享，还可以在用户空间之间共享。

## 9.1 Generate BPF

```
/ Regenerate forces the regeneration of endpoint programs & policy
// Should only be called with e.state at StateWaitingToRegenerate,
// StateWaitingForIdentity, or StateRestoring
func (e *Endpoint) Regenerate(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool {
		done := make(chan bool, 1)
		
		// This may block if the Endpoint's EventQueue is full. This has to be done
    
    epEvent := eventqueue.NewEvent(&EndpointRegenerationEvent{
      regenContext: regenContext,
      ep:           e,
    })
    
    // synchronously as some callers depend on the fact that the event is
    // synchronously enqueued.
    resChan, err := e.eventQueue.Enqueue(epEvent)
    
    go func() {
    		result, ok := <-resChan
    }
}
```

EndpointRegenerationEvent的Handle方法中

```

// Handle handles the regeneration event for the endpoint.
func (ev *EndpointRegenerationEvent) Handle(res chan interface{}) {
		err := e.rlockAlive()
		
		// We should only queue the request after we use all the endpoint's
    // lock/unlock. Otherwise this can get a deadlock if the endpoint is
    // being deleted at the same time. More info PR-1777.
    doneFunc, err := e.owner.QueueEndpointBuild(regenContext.parentContext, uint64(e.ID))
    
    err = ev.ep.regenerate(ev.regenContext)
    doneFunc()
}
```



```
func (e *Endpoint) regenerate(ctx *regenerationContext) (retErr error) {
		origDir := e.StateDirectoryPath()
		ctx.datapathRegenerationContext.currentDir = origDir
		
		// This is the temporary directory to store the generated headers,
    // the original existing directory is not overwritten until the
    // entire generation process has succeeded.
    tmpDir := e.NextDirectoryPath()
    ctx.datapathRegenerationContext.nextDir = tmpDir
    os.MkdirAll(tmpDir, 0777);
    
    revision, err = e.regenerateBPF(ctx)
    return e.updateRealizedState(stats, origDir, revision)
}
```

由于BPF代码的重新生成是一系列基于文件的操作，重新生成过程首先会为这一过程准备好工作目录，随后调用端点的`regenerateBPF`方法。

`regenerateBPF`方法会重写所有头文件，并更新所有BPF映射，以反映指定端点的状态。

```
// regenerateBPF rewrites all headers and updates all BPF maps to reflect the
// specified endpoint.
// ReloadDatapath forces the datapath programs to be reloaded. It does
// not guarantee recompilation of the programs.
// Must be called with endpoint.mutex not held and endpoint.buildMutex held.
//
// Returns the policy revision number when the regeneration has called,
// Whether the new state dir is populated with all new BPF state files,
// and an error if something failed.
func (e *Endpoint) regenerateBPF(regenContext *regenerationContext) (revnum uint64, reterr error) {
		err = e.runPreCompilationSteps(regenContext, rules)
		
		<-datapathRegenCtxt.ctCleaned
		
		err = e.realizeBPFState(regenContext)
		stats.mapSync.Start()
		err = lxcmap.WriteEndpoint(datapathRegenCtxt.epInfoCache)
		
		// Signal that BPF program has been generated.
    // The endpoint has at least L3/L4 connectivity at this point.
    e.closeBPFProgramChannel()
    
    // Allow another builder to start while we wait for the proxy
    if regenContext.DoneFunc != nil {
      regenContext.DoneFunc()
    }
    
    e.ctCleaned = true
    
    // Synchronously try to update PolicyMap for this endpoint. If any
    // part of updating the PolicyMap fails, bail out.
    // Unfortunately, this means that the map will be in an inconsistent
    // state with the current program (if it exists) for this endpoint.
    // GH-3897 would fix this by creating a new map to do an atomic swap
    // with the old one.
    //
    // This must be done after allocating the new redirects, to update the
    // policy map with the new proxy ports.
    stats.mapSync.Start()
    err = e.syncPolicyMap()
    
    return datapathRegenCtxt.epInfoCache.revision, err
}
```

BPF源代码（使用受限的C语言）在`e.runPreCompilationSteps`中生成，并在该函数的末尾通过`writeHeaderfile`写入文件中：

```
// runPreCompilationSteps runs all of the regeneration steps that are necessary
// right before compiling the BPF for the given endpoint.
// The endpoint mutex must not be held.
//
// Returns whether the headerfile changed and/or an error.
func (e *Endpoint) runPreCompilationSteps(regenContext *regenerationContext, rules restore.DNSRules) (preCompilationError error) {
		policyResult, err := e.regeneratePolicy(stats)
		
		currentDir := datapathRegenCtxt.currentDir
		nextDir := datapathRegenCtxt.nextDir
		
		if e.policyMap == nil {
				e.policyMap, err = policymap.OpenOrCreate(e.policyMapPath())
				
				// Synchronize the in-memory realized state with BPF map entries,
        // so that any potential discrepancy between desired and realized
        // state would be dealt with by the following e.syncPolicyMap.
        pm, err := e.dumpPolicyMapToMapState()
        if err != nil {
          return err
        }
        e.realizedPolicy.SetPolicyMap(pm)
        e.updatePolicyMapPressureMetric()
		}
		
		// Only generate & populate policy map if a security identity is set up for
    // this endpoint.
    if e.SecurityIdentity != nil {
    		
    		err, networkPolicyRevertFunc := e.updateNetworkPolicy(datapathRegenCtxt.proxyWaitGroup)
    }
    
   	e.writeHeaderfile(nextDir);
}
```

在回过来看realizeBPFState

```
func (e *Endpoint) realizeBPFState(regenContext *regenerationContext) (err error) {
		// Compile and install BPF programs for this endpoint
		templateHash, err := e.owner.Datapath().Loader().ReloadDatapath(datapathRegenCtxt.completionCtx, datapathRegenCtxt.epInfoCache, &stats.datapathRealization)
		
		os.WriteFile(filepath.Join(datapathRegenCtxt.nextDir, defaults.TemplateIDPath), []byte(templateHash+"\n")
		
		e.bpfHeaderfileHash = datapathRegenCtxt.bpfHeaderfilesHash
}
```

`CompileAndLoad`负责编译并重新加载数据路径程序（即BPF代码）。

`ReloadDatapath`则强制重新加载数据路径程序，但并不能保证程序会被重新编译。

## 9.2 Compile and link

ReloadDatapath 重新加载指定端点的 BPF 数据路径程序，它会尝试寻找一个预编译的模板数据路径对象来使用，以避免耗时的编译操作。只有在缓存中没有与指定端点配置参数相同的现有模板时，此函数才会为该配置编译一个新的模板。如果缓存中不存在相同 EndpointConfiguration 的条目，且多个 goroutine 尝试使用相同的配置参数并发调用 CompileOrLoad，此函数将会阻塞。当第一个 goroutine 完成模板的编译后，所有其他 CompileOrLoad 的调用将被释放。

```
spec, hash, err := l.templateCache.fetchOrCompile(ctx, cfg, ep, &dirs, stats)
err = l.reloadDatapath(ep, spec)
```

```
// fetchOrCompile attempts to fetch the path to the datapath object
// corresponding to the provided endpoint configuration, or if this
// configuration is not yet compiled, compiles it. It will block if multiple
// threads attempt to concurrently fetchOrCompile a template binary for the
// same set of EndpointConfiguration.
//
// Returns a copy of the compiled and parsed ELF and a hash identifying a cached entry.
func (o *objectCache) fetchOrCompile(){
		// Only allow a single concurrent compilation per hash.
    obj := o.serialize(hash)
    defer obj.Unlock()
		
		path, err := o.build(ctx, nodeCfg, cfg, stats, dir, hash)
		
		obj.spec, err = bpf.LoadCollectionSpec(path)
}
```

缓存中如果不存在BPF程序，build()会编译并缓存

```
// build attempts to compile and cache a datapath template object file
// corresponding to the specified endpoint configuration.
func (o *objectCache) build(){
		err = compileDatapath(ctx, dir, isHost, log)
}
```

实际的编译和链接工作在 `compile()` 函数中完成，该函数调用 `clang/llvm` 将 C 源代码编译并链接为 BPF 字节码，位于 `pkt/datapath/loader/compile.go` 文件中。

```
func compile(ctx context.Context, prog *progInfo, dir *directoryInfo) (string, error) {

		compileArgs := append(testIncludes,
		fmt.Sprintf("-I%s", path.Join(dir.Runtime, "globals")),
		fmt.Sprintf("-I%s", dir.State),
		fmt.Sprintf("-I%s", dir.Library),
		fmt.Sprintf("-I%s", path.Join(dir.Library, "include")),
    )

    switch prog.OutputType {
    case outputSource:
      compileArgs = append(compileArgs, "-E") // Preprocessor
    case outputObject:
      compileArgs = append(compileArgs, "-g")
    }

    compileArgs = append(compileArgs, standardCFlags...)
    compileArgs = append(compileArgs, fmt.Sprintf("-D__NR_CPUS__=%d", possibleCPUs))
    compileArgs = append(compileArgs, "-mcpu="+getBPFCPU())
    compileArgs = append(compileArgs, prog.Options...)
    compileArgs = append(compileArgs,
      "-c", path.Join(dir.Library, prog.Source),
      "-o", "-", // Always output to stdout
    )
    
    compileCmd, cancelCompile := exec.WithCancel(ctx, compiler, compileArgs...)
    output, err := os.Create(prog.AbsoluteOutput(dir))
    err := compileCmd.Run();
}
```

## 9.3 Reload datapath

link的过程在reloadDatapath中

```
// reloadDatapath loads programs in spec into the device used by ep.
//
// spec is modified by the method and it is the callers responsibility to copy
// it if necessary.
func (l *loader) reloadDatapath(ep datapath.Endpoint, spec *ebpf.CollectionSpec) error {
		if ep.IsHost() {
				l.reloadHostDatapath(ep, spec, devices);
		} else {
				coll, commit, err := loadDatapath(spec, ELFMapSubstitutions(ep), ELFVariableSubstitutions(ep))
				iface, err := safenetlink.LinkByName(device)
				linkDir := bpffsEndpointLinksDir(bpf.CiliumPath(), ep)
				attachSKBProgram(iface, coll.Programs[symbolFromEndpoint], symbolFromEndpoint,
				linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX)
		}
}
```

`loadDatapath` 返回一个 `Collection`，给定 ELF 对象，根据 `mapRenames` 重命名映射，并覆盖给定的常量。成功时，返回一个函数，该函数将待处理的映射固定提交到 BPF 文件系统，适用于那些被发现与其固定副本不兼容的映射，或具有某些修改默认固定行为标志的映射。当在循环中附加来自同一 ELF 的多个程序时，返回的函数应仅在所有入口点都已附加后运行。例如，先附加 `bpf_host.c:cil_to_netdev` 和 `cil_from_netdev`，然后再调用返回的函数，否则将发生尾部调用缺失的情况 1。

```
func loadDatapath(spec *ebpf.CollectionSpec, mapRenames map[string]string, constants map[string]uint64) (*ebpf.Collection, func() error, error) {
		spec, err := renameMaps(spec, mapRenames)
		
		if err := bpf.MkdirBPF(pinPath)
		coll, commit, err := bpf.LoadCollection(spec, &collOpts)
		
		resolveAndInsertCalls(coll, policymap.PolicyCallMapName, policyProgs);
}
```

如果 ELF 文件中包含策略调用映射之一，解析并将其引用的程序插入到映射中。这始终需要在附加 ELF 的入口点之前完成，但要在 ELF 内部的尾调用映射（cilium_calls）被填充之后进行，因为这样做意味着 ELF 的程序通过其策略程序变得可达，而策略程序持有对端点 cilium_calls 的引用。因此，插入策略程序被视为一种“附加”操作，只是不通过典型的 bpf 钩子进行。例如，数据包可以进入 to-container，跳转到 bpf_host 策略程序，然后跳转到由以下循环安装的端点的策略程序。如果我们允许数据包通过其 tc 钩子进入端点的 bpf 程序，所有这些准备工作需要首先完成，否则可能会丢失尾调用。