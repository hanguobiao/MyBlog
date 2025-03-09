---
title: KubeBlocks源码笔记五--kbagent
date: 2025-03-05
update: 2025-03-05
comment: false
tags:
  - kubeblocks
categories:
  - kubeblocks
---

KBAgent是Kubeblocks的“代理”，通过sidecar的形式与数据库容器部署在一起（如果需要使用到KBAgent的功能就在创建时注入该sidecar），其作用包括命令通道（lifecycle and more）、配置变更等。本质上是一个http服务器，Kubeblocks通过发送HTTP请求来触发KBAgent的功能。

*<!--more-->*


# 启动流程

启动的main.go文件中，会首先Initialize，获取到所有的lifecycleActions脚本，和probe。之后将这些注册到KBAgent中，并启动HTTP Server。当这些被触发时，就会执行用户定义好的脚本。

```
serving, err := kbagent.Launch(logger, serverConfig)
if err != nil {
  panic(err)
}
if serving {
  stop := make(chan os.Signal, 1)
  signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
  <-stop
}

```

```
func Launch(logger logr.Logger, config server.Config) (bool, error) {
    envVars := util.EnvL2M(os.Environ())

    // initialize kb-agent
    services, err := initialize(logger, envVars)
    if err != nil {
       return false, errors.Wrap(err, "init action handlers failed")
    }
    if config.Server {
       return true, runAsServer(logger, config, services)
    }
    return false, runAsWorker(logger, services, envVars)
}
```

lifecycleActions的脚本是从KBAgent所在Container的环境变量中获取。该ENV是Kubeblocks自动注入的。

-  "KB_AGENT_ACTION"
-  "KB_AGENT_PROBE"
-  "KB_AGENT_STREAMING"

```
func getActionProbeNStreamingEnvValues(envVars map[string]string) (string, string, string) {
    da, ok := envVars[actionEnvName]
    if !ok {
       return "", "", ""
    }
    dp, ok := envVars[probeEnvName]
    if !ok {
       return da, "", ""
    }
    ds, ok := envVars[streamingEnvName]
    if !ok {
       return da, dp, ""
    }
    return da, dp, ds
}
```

```
bash-4.4# echo $KB_AGENT_ACTION
[{"name":"postProvision","exec":{"command":["bash","-c","/scripts/mysql-orchestrator-register.sh"]}},{"name":"preTerminate","exec":{"command":["bash","-c","curl http://${ORC_ENDPOINTS%%:*}:${ORC_PORTS}/api/forget-cluster/${CLUSTER_NAME} || true"]}},{"name":"memberLeave","exec":{"command":["/bin/bash","-c","set +e\nmaster_from_orc=$(/kubeblocks/orchestrator-client -c which-cluster-master -i $CLUSTER_NAME)\nlast_digit=${KB_LEAVE_MEMBER_POD_NAME##*-}\nself_service_name=$(echo \"${CLUSTER_COMPONENT_NAME}_mysql_${last_digit}\" | tr '_' '-' | tr '[:upper:]' '[:lower:]' )\nif [ \"${self_service_name%%:*}\" == \"${master_from_orc%%:*}\" ]; then\n /kubeblocks/orchestrator-client -c force-master-failover -i $CLUSTER_NAME\n local timeout=30\n local start_time=$(date +%s)\n local current_time\n while true; do\n current_time=$(date +%s)\n if [ $((current_time - start_time)) -gt $timeout ]; then\n break\n fi\n master_from_orc=$(/kubeblocks/orchestrator-client -c which-cluster-master -i $CLUSTER_NAME)\n if [ \"${self_service_name%%:*}\" != \"${master_from_orc%%:*}\" ]; then\n break\n fi\n sleep 1\n done\nfi\n/kubeblocks/orchestrator-client -c reset-replica -i ${self_service_name}\n/kubeblocks/orchestrator-client -c forget -i ${self_service_name}\n"]}},{"name":"accountProvision","exec":{"command":["/bin/sh","-c","set -ex\neval statement=\\\"${KB_ACCOUNT_STATEMENT}\\\"\nmysql -u${MYSQL_ROOT_USER} -p${MYSQL_ROOT_PASSWORD} -P3306 -h127.0.0.1 -e \"${statement}\"\n"]}},{"name":"roleProbe","exec":{"command":["/bin/bash","-c","topology_info=$(/kubeblocks/orchestrator-client -c topology -i $CLUSTER_NAME) || true\nif [[ $topology_info == \"\" ]]; then\n echo -n \"secondary\"\n exit 0\nfi\n\nfirst_line=$(echo \"$topology_info\" | head -n 1)\ncleaned_line=$(echo \"$first_line\" | tr -d '[]')\nIFS=',' read -ra status_array \u003c\u003c\u003c \"$cleaned_line\"\nstatus=\"${status_array[1]}\"\nif [ \"$status\" != \"ok\" ]; then\n exit 0\nfi\n\naddress_port=$(echo \"$first_line\" | awk '{print $1}')\nmaster_from_orc=\"${address_port%:*}\"\nlast_digit=${KB_AGENT_POD_NAME##*-}\nself_service_name=$(echo \"${CLUSTER_COMPONENT_NAME}_mysql_${last_digit}\" | tr '_' '-' | tr '[:upper:]' '[:lower:]' )\nif [ \"$master_from_orc\" == \"${self_service_name}\" ]; then\n echo -n \"primary\"\nelse\n echo -n \"secondary\"\nfi\n"]}}]
```

之后会一次创建几个Service

```
func New(logger logr.Logger, actions []proto.Action, probes []proto.Probe, streaming []string) ([]Service, error) {
    sa, err := newActionService(logger, actions)
    if err != nil {
       return nil, err
    }
    sp, err := newProbeService(logger, sa, probes)
    if err != nil {
       return nil, err
    }
    ss, err := newStreamingService(logger, sa, streaming)
    if err != nil {
       return nil, err
    }
    return []Service{sa, sp, ss}, nil
}
```



runAsServer中会依次调用之前生成的Service的start接口，Service的定义和方法如下所示。

```go
func runAsServer(logger logr.Logger, config server.Config, services []service.Service) error {
    if config.Port == config.StreamingPort {
       return errors.New("HTTP port and streaming port are the same")
    }

    // start all services first
    for i := range services {
       if err := services[i].Start(); err != nil {
          logger.Error(err, fmt.Sprintf("start service %s failed", services[i].Kind()))
          return err
       }
       logger.Info(fmt.Sprintf("service %s started...", services[i].Kind()))
    }

    // start the HTTP server
    httpServer := server.NewHTTPServer(logger, config, services)
    err := httpServer.StartNonBlocking()
    if err != nil {
       return errors.Wrap(err, "failed to start the HTTP server")
    }

    // start the streaming server
    streamingServer := server.NewStreamingServer(logger, config, streamingService(services))
    err = streamingServer.StartNonBlocking()
    if err != nil {
       return errors.Wrap(err, "failed to start the streaming server")
    }
    return nil
}
```

```go
type Service interface {
	Kind() string
	URI() string

	Start() error

	HandleRequest(ctx context.Context, payload []byte) ([]byte, error)
}
```

# Service Start

Actions的start方法为空，Probe的会启动probeRunner，通过启动协程来周期性执行probe任务。probeRunner会启动两个循环，包括ReportLoop用于返回event，和runLoop用于实际执行指令和记录event

```go
func (r *probeRunner) run(probe *proto.Probe) {
	r.logger.Info("probe started", "config", probe)

	if probe.InitialDelaySeconds > 0 {
		time.Sleep(time.Duration(probe.InitialDelaySeconds) * time.Second)
	}

	// launch report loop first
	r.launchReportLoop(probe)

	r.launchRunLoop(probe)
}
```

# Service Handle

probe的HandleRequest的实现为空，action的HandlRequest就是具体处理请求的函数

```
func (s *actionService) HandleRequest(ctx context.Context, payload []byte) ([]byte, error) {
	req, err := s.decode(payload)
	if err != nil {
		return s.encode(nil, err), nil
	}
	resp, err := s.handleRequest(ctx, req)
	result := string(resp)
	if err != nil {
		result = err.Error()
	}
	s.logger.Info("Action Executed", "action", req.Action, "result", result)
	return s.encode(resp, err), nil
}
```

支持同步的执行方式，也提供了非阻塞的异步方式，会立即返回inprocessing的error，之后调用该Actions会检查是否有正在执行的channel，如果有返回结果。

```
func (s *actionService) handleExecActionNonBlocking(ctx context.Context, req *proto.ActionRequest, action *proto.Action) ([]byte, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	running, ok := s.runningActions[req.Action]
	if !ok {
		resultChan, err := runCommandNonBlocking(ctx, action.Exec, req.Parameters, req.TimeoutSeconds)
		if err != nil {
			return nil, err
		}
		running = &runningAction{
			resultChan: resultChan,
		}
		s.runningActions[req.Action] = running
	}
	result := gather(running.resultChan)
	if result == nil {
		return nil, proto.ErrInProgress
	}
	delete(s.runningActions, req.Action)
	if (*result).err != nil {
		return nil, (*result).err
	}
	return (*result).stdout.Bytes(), nil
}

```

在KB中KBAgent的注入逻辑在func BuildSynthesizedComponent()，在生成synthesizedComp会判断是否需要使用kbagent的功能，如果需要就生成KBAgent的container。

# Lifecycle Action

API介绍见：

KBAgent目前主要功能就是支持Lifecycle Action的实现

