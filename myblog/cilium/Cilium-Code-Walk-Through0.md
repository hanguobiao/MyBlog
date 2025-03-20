---
title: (转+译)Cilium Code Walk Through - What's Inside a Cilium Daemon?
date: 2025-02-27
update: 2025-02-28
comment: false
tags:
  - Cilium
categories:
  - Cilium
---

由于主要思路仍然遵循之前的博客，只是按照最新1.16版本的代码重新组织，行文组织为更适合自己的形式。目前以自用为主

Cilium主要以Daemonset的形式在每个节点中部署

这里分析Daemonset的initContainer和MainContainer分别做了哪些工作

*<!--more-->*


# InitContainer

## config

```
- name: config
  command:
  - cilium
  - build-config
  image: quay.io/cilium/cilium:v1.14.4@sha256:4981767b787c69126e190e33aee93d5a076639083c21f0e7c29596a519c64a2e
  imagePullPolicy: IfNotPresent
  volumeMounts:
  - mountPath: /tmp
    name: tmp
```

config容器执行的命令是cilium build-config



## mount-cgroup

```yaml
- name: mount-cgroup
  command:
  - sh
  - -ec
  - |
    cp /usr/bin/cilium-mount /hostbin/cilium-mount;
    nsenter --cgroup=/hostproc/1/ns/cgroup --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-mount" $CGROUP_ROOT;
    rm /hostbin/cilium-mount    
  env:
  - name: CGROUP_ROOT
    value: /run/cilium/cgroupv2
  - name: BIN_PATH
    value: /opt/cni/bin
  image: quay.io/cilium/cilium:v1.14.4@sha256:4981767b787c69126e190e33aee93d5a076639083c21f0e7c29596a519c64a2e
  securityContext:
    capabilities:
      add:
      - SYS_ADMIN
      - SYS_CHROOT
      - SYS_PTRACE
      drop:
      - ALL
    seLinuxOptions:
      level: s0
      type: spc_t
  volumeMounts:
  - mountPath: /hostproc
    name: hostproc
  - mountPath: /hostbin
    name: cni-path
```

mount-cgroup的作用是将cgroup v2 mount到 /run/cilium/cgroupv2

Cilium 使用 cgroup v2 来实施网络策略、监控和其他关键功能。例如，Cilium 可能用于确保只有经过验证的网络流量可以进入和离开容器化的应用程序，或者用于控制容器可以使用多少系统资源等等。

## apply-sysctl-overwrites

```yaml
- name: apply-sysctl-overwrites
  command:
  - sh
  - -ec
  - |
    cp /usr/bin/cilium-sysctlfix /hostbin/cilium-sysctlfix;
    nsenter --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-sysctlfix";
    rm /hostbin/cilium-sysctlfix    
  env:
  - name: BIN_PATH
    value: /opt/cni/bin
  image: quay.io/cilium/cilium:v1.14.4@sha256:4981767b787c69126e190e33aee93d5a076639083c21f0e7c29596a519c64a2e
  securityContext:
    capabilities:
      add:
      - SYS_ADMIN
      - SYS_CHROOT
      - SYS_PTRACE
      drop:
      - ALL
    seLinuxOptions:
      level: s0
      type: spc_t
  volumeMounts:
  - mountPath: /hostproc
    name: hostproc
  - mountPath: /hostbin
    name: cni-path
```

用于修改系统参数，以适配Cilium的部署要求

## mount-bpf-fs

```yaml
- name: mount-bpf-fs
  args:
  - mount | grep "/sys/fs/bpf type bpf" || mount -t bpf bpf /sys/fs/bpf
  command:
  - /bin/bash
  - -c
  - --
  image: quay.io/cilium/cilium:v1.14.4@sha256:4981767b787c69126e190e33aee93d5a076639083c21f0e7c29596a519c64a2e
  securityContext:
    privileged: true
  volumeMounts:
  - mountPath: /sys/fs/bpf
    mountPropagation: Bidirectional
    name: bpf-maps
```

这个 init-container 使得进程可以通过文件系统接口来访问 BPF 虚拟文件系统，从而加载和管理 BPF 程序和 maps。提供了一个持久化的存储空间来存储 BPF 对象，这些对象可以在**进程之间共享**，即使是在进程终止后。

## clean-cilium-state

```yaml
- name: clean-cilium-state
  command:
  - /init-container.sh
  env:
  - name: CILIUM_ALL_STATE
    valueFrom:
      configMapKeyRef:
        key: clean-cilium-state
        name: cilium-config
        optional: true
  - name: CILIUM_BPF_STATE
    valueFrom:
      configMapKeyRef:
        key: clean-cilium-bpf-state
        name: cilium-config
        optional: true
  - name: KUBERNETES_SERVICE_HOST
    value: 192.168.1.200
  - name: KUBERNETES_SERVICE_PORT
    value: "6443"
  image: quay.io/cilium/cilium:v1.14.4@sha256:4981767b787c69126e190e33aee93d5a076639083c21f0e7c29596a519c64a2e
  resources:
    requests:
      cpu: 100m
      memory: 100Mi
  securityContext:
    capabilities:
      add:
      - NET_ADMIN
      - SYS_MODULE
      - SYS_ADMIN
      - SYS_RESOURCE
      drop:
      - ALL
    seLinuxOptions:
      level: s0
      type: spc_t
  volumeMounts:
  - mountPath: /sys/fs/bpf
    name: bpf-maps
  - mountPath: /run/cilium/cgroupv2
    mountPropagation: HostToContainer
    name: cilium-cgroup
  - mountPath: /var/run/cilium
    name: cilium-run
```

这个容器主要做的就是**清理**一些跟 Cilium 相关的网络接口上的配置，主要是防止 cilium-agent **启动**或者**重启**的时候一些网络配置的残留会影响 Cilium 的正常运作。

## install-cni-binaries

```yaml
- name: install-cni-binaries
  command:
  - /install-plugin.sh
  image: quay.io/cilium/cilium:v1.14.4@sha256:4981767b787c69126e190e33aee93d5a076639083c21f0e7c29596a519c64a2e
  resources:
    requests:
      cpu: 100m
      memory: 10Mi
  securityContext:
    capabilities:
      drop:
      - ALL
    seLinuxOptions:
      level: s0
      type: spc_t
  volumeMounts:
  - mountPath: /host/opt/cni/bin
    name: cni-path
```

CNI 都会通过这样的方式将 CNI 的二进制放到宿主机的 /etc/cni/net.d/ 这个目录里。

# MainContaienr

```yaml
- name: cilium-agent
          image: "quay.io/cilium/cilium:v1.14.4"
          command:
            - cilium-agent
          args:
            - --config-dir=/tmp/cilium/config-map
          startupProbe:
            httpGet:
              host: "127.0.0.1"
              path: /healthz
              port: 9879
              scheme: HTTP
              httpHeaders:
                - name: "brief"
                  value: "true"
            failureThreshold: 105
            periodSeconds: 2
            successThreshold: 1
          livenessProbe:
            httpGet:
              host: "127.0.0.1"
              path: /healthz
              port: 9879
              scheme: HTTP
              httpHeaders:
                - name: "brief"
                  value: "true"
            periodSeconds: 30
            successThreshold: 1
            failureThreshold: 10
            timeoutSeconds: 5
          readinessProbe:
            httpGet:
              host: "127.0.0.1"
              path: /healthz
              port: 9879
              scheme: HTTP
              httpHeaders:
                - name: "brief"
                  value: "true"
            periodSeconds: 30
            successThreshold: 1
            failureThreshold: 3
            timeoutSeconds: 5
          env:
            - name: K8S_NODE_NAME
              valueFrom:
                fieldRef:
                  apiVersion: v1
                  fieldPath: spec.nodeName
            - name: CILIUM_K8S_NAMESPACE
              valueFrom:
                fieldRef:
                  apiVersion: v1
                  fieldPath: metadata.namespace
            - name: CILIUM_CLUSTERMESH_CONFIG
              value: /var/lib/cilium/clustermesh/
            - name: KUBERNETES_SERVICE_HOST
              value: hh-k8s-noah-sc-staging001-master.api.vip.com
          lifecycle:
            postStart:
              exec:
                command:
                  - "bash"
                  - "-c"
                  - |
                    set -o errexit
                    set -o pipefail
                    set -o nounset
                    
                    # When running in AWS ENI mode, it's likely that 'aws-node' has
                    # had a chance to install SNAT iptables rules. These can result
                    # in dropped traffic, so we should attempt to remove them.
                    # We do it using a 'postStart' hook since this may need to run
                    # for nodes which might have already been init'ed but may still
                    # have dangling rules. This is safe because there are no
                    # dependencies on anything that is part of the startup script
                    # itself, and can be safely run multiple times per node (e.g. in
                    # case of a restart).
                    if [[ "$(iptables-save | grep -c 'AWS-SNAT-CHAIN|AWS-CONNMARK-CHAIN')" != "0" ]];
                    then
                        echo 'Deleting iptables rules created by the AWS CNI VPC plugin'
                        iptables-save | grep -v 'AWS-SNAT-CHAIN|AWS-CONNMARK-CHAIN' | iptables-restore
                    fi
                    echo 'Done!'                    

            preStop:
              exec:
                command:
                  - /cni-uninstall.sh
          securityContext:
            seLinuxOptions:
              level: s0
              type: spc_t
            capabilities:
              add:
                - CHOWN
                - KILL
                - NET_ADMIN
                - NET_RAW
                - IPC_LOCK
                - SYS_MODULE
                - SYS_ADMIN
                - SYS_RESOURCE
                - DAC_OVERRIDE
                - FOWNER
                - SETGID
                - SETUID
              drop:
                - ALL
          terminationMessagePolicy: FallbackToLogsOnError
          volumeMounts:
            # Unprivileged containers need to mount /proc/sys/net from the host
            # to have write access
            - mountPath: /host/proc/sys/net
              name: host-proc-sys-net
              # /proc/sys/net
            # Unprivileged containers need to mount /proc/sys/kernel from the host
            # to have write access
            - mountPath: /host/proc/sys/kernel
              name: host-proc-sys-kernel
              # /host/proc/sys/kernel
            - name: bpf-maps
              mountPath: /sys/fs/bpf
              # /sys/fs/bpf
              # Unprivileged containers can't set mount propagation to bidirectional
              # in this case we will mount the bpf fs from an init container that
              # is privileged and set the mount propagation from host to container
              # in Cilium.
              mountPropagation: HostToContainer
            - name: cilium-run
              mountPath: /var/run/cilium
            - name: etc-cni-netd
              mountPath: /host/etc/cni/net.d
            - name: clustermesh-secrets
              mountPath: /var/lib/cilium/clustermesh
              readOnly: true
            - name: cni-configuration
              mountPath: /tmp/cni-configuration
              readOnly: true
              # Needed to be able to load kernel modules
            - name: lib-modules
              mountPath: /lib/modules
              # /lib/modules
              readOnly: true
            - name: xtables-lock
              mountPath: /run/xtables.lock
            - name: hubble-tls
              mountPath: /var/lib/cilium/tls/hubble
              readOnly: true
            - name: tmp
              mountPath: /tmp
```