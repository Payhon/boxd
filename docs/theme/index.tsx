import './index.css';

import {
  HomeLayout as BasicHomeLayout,
  type HomeLayoutProps,
} from '@rspress/core/theme-original';

function ProjectStatus() {
  return (
    <main className="boxd-home-content">
      <section className="boxd-section">
        <span className="boxd-eyebrow">Open source · MIT</span>
        <h2>为本地 Agent 工作流设计</h2>
        <p className="boxd-lede">
          boxd 将 API、生命周期、文件、Git、快照、调度和 Browser 能力收敛到一个本地控制面，
          让开发者可以在自己的 Mac 上获得可清理、可恢复、按 Box 隔离的执行环境。
        </p>
        <div className="boxd-grid">
          <div className="boxd-card">
            <strong>替换 endpoint，不替换心智模型</strong>
            <p>继续使用公开的 @upstash/box SDK，通过显式 baseUrl 指向本地服务。</p>
          </div>
          <div className="boxd-card">
            <strong>microVM 是隔离边界</strong>
            <p>每个 Box 运行在独立 Linux microVM 中；guest 工作负载不会作为普通宿主进程直接执行。</p>
          </div>
          <div className="boxd-card">
            <strong>不支持就明确失败</strong>
            <p>尚未实现的能力返回 501 feature_not_supported，不会接受参数后静默忽略。</p>
          </div>
        </div>
      </section>

      <section className="boxd-section boxd-section--status">
        <span className="boxd-eyebrow">Current evidence</span>
        <h2>当前状态，一眼看清</h2>
        <div className="boxd-metrics">
          <div className="boxd-metric"><b>0.6.3</b><span>固定的公开 SDK 基线</span></div>
          <div className="boxd-metric"><b>82</b><span>公开 SDK contract cases</span></div>
          <div className="boxd-metric"><b>macOS 14+</b><span>首发 Apple Silicon 宿主</span></div>
          <div className="boxd-metric"><b>Phase 4</b><span>生产加固进行中</span></div>
        </div>
        <div className="boxd-callout">
          <strong>兼容性声明</strong>
          <p>
            macOS Apple Silicon 已有真实 HVF、Node/Browser runtime 与数据库矩阵证据；Linux KVM、
            十种 runtime 矩阵、受保护环境的 authenticated differential、正式签名/notarization 与
            升级回滚证据仍是发布门禁。在全部门禁通过前，boxd 只声明兼容子集。
          </p>
          <a href="./concepts/compatibility">查看完整兼容性边界 →</a>
        </div>
      </section>

      <section className="boxd-section boxd-cta">
        <div>
          <span className="boxd-eyebrow">Start locally</span>
          <h2>从仓库到第一个 Box</h2>
          <p>
            控制面构建很直接；真实 microVM 还需要固定版本 libkrun、HVF entitlement 和签名 runtime bundle。
            向导会从空白环境开始解释每一步。
          </p>
        </div>
        <div className="boxd-cta__actions">
          <a className="boxd-button boxd-button--brand" href="./guide/quick-start">5 分钟开始</a>
          <a className="boxd-button" href="./guide/source-build">完整源码向导</a>
        </div>
      </section>
    </main>
  );
}

export function HomeLayout(props: HomeLayoutProps) {
  return <BasicHomeLayout {...props} afterFeatures={<ProjectStatus />} />;
}

export * from '@rspress/core/theme-original';
