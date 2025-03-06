Deployment应该是无状态应用最常用的部署形式，调谐过程的代码在Controller/deployment

syncDeployment函数是deployment的handler函数，负责在接受到有关事件的时候进行调谐

```
func (dc *DeploymentController) syncDeployment(ctx context.Context, key string) error {
		//1. 获取name、namespace 并由此获得deploy实例
		//2. 通过selector获得所有RS，进一步获取所有的POD
		//3. 
}
```

来看最关键的sync函数，首先会根据获取到所有的新的，旧的RS，通过timesstamp来确定最新的RS，在所有的RS list中筛选出旧的RS。之后会根据新旧RS调整Pod的数量

```
func (dc *DeploymentController) sync(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) error {
    newRS, oldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, false)
    if err != nil {
       return err
    }
    if err := dc.scale(ctx, d, newRS, oldRSs); err != nil {
       // If we get an error while trying to scale, the deployment will be requeued
       // so we can abort this resync
       return err
    }

    // Clean up the deployment when it's paused and no rollback is in flight.
    if d.Spec.Paused && getRollbackTo(d) == nil {
       if err := dc.cleanupDeployment(ctx, oldRSs, d); err != nil {
          return err
       }
    }

    allRSs := append(oldRSs, newRS)
    return dc.syncDeploymentStatus(ctx, allRSs, newRS, d)
}
```

从新旧RS 中筛选出replicas > 0的RS定义为active RS。如果只有一个active的RS，就扩容到deployment的replica，如果没有active的RS

