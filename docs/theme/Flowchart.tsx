import { useEffect, useId, useRef, useState } from 'react';

type FlowchartSize = 'compact' | 'standard' | 'wide';

interface FlowchartProps {
  chart: string;
  title: string;
  description?: string;
  size?: FlowchartSize;
}

export default function Flowchart({
  chart,
  title,
  description,
  size = 'standard',
}: FlowchartProps) {
  const reactId = useId();
  const canvasRef = useRef<HTMLDivElement>(null);
  const renderCountRef = useRef(0);
  const [status, setStatus] = useState<'loading' | 'ready' | 'error'>('loading');

  useEffect(() => {
    let cancelled = false;
    let requestedRender = 0;

    const renderDiagram = async () => {
      const request = ++requestedRender;
      setStatus('loading');

      try {
        const { default: mermaid } = await import('mermaid');
        const dark = document.documentElement.classList.contains('dark');

        mermaid.initialize({
          startOnLoad: false,
          securityLevel: 'strict',
          theme: 'base',
          fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif',
          themeVariables: dark
            ? {
                background: '#0b1220',
                primaryColor: '#123c3b',
                primaryBorderColor: '#46e6ce',
                primaryTextColor: '#f4fbff',
                secondaryColor: '#1a2740',
                secondaryBorderColor: '#7895ff',
                secondaryTextColor: '#f4fbff',
                tertiaryColor: '#111c2d',
                tertiaryBorderColor: '#40516a',
                tertiaryTextColor: '#dce8f5',
                lineColor: '#8ba0b9',
                clusterBkg: '#101a2a',
                clusterBorder: '#344760',
                edgeLabelBackground: '#0b1220',
              }
            : {
                background: '#ffffff',
                primaryColor: '#e5f8f4',
                primaryBorderColor: '#078779',
                primaryTextColor: '#07111f',
                secondaryColor: '#edf1ff',
                secondaryBorderColor: '#6c8dff',
                secondaryTextColor: '#07111f',
                tertiaryColor: '#f6f8fb',
                tertiaryBorderColor: '#b8c4d4',
                tertiaryTextColor: '#182539',
                lineColor: '#60748c',
                clusterBkg: '#f7fafc',
                clusterBorder: '#ced8e5',
                edgeLabelBackground: '#ffffff',
              },
          flowchart: {
            curve: 'basis',
            htmlLabels: true,
            nodeSpacing: 42,
            rankSpacing: 52,
            padding: 18,
            useMaxWidth: false,
          },
        });

        const renderId = `boxd-flowchart-${reactId.replace(/[^a-zA-Z0-9]/g, '')}-${++renderCountRef.current}`;
        const { svg, bindFunctions } = await mermaid.render(renderId, chart);

        if (cancelled || request !== requestedRender || !canvasRef.current) return;

        canvasRef.current.innerHTML = svg;
        bindFunctions?.(canvasRef.current);
        setStatus('ready');
      } catch (error) {
        if (cancelled || request !== requestedRender) return;
        console.error(`Failed to render flowchart "${title}"`, error);
        setStatus('error');
      }
    };

    void renderDiagram();

    const themeObserver = new MutationObserver(() => {
      void renderDiagram();
    });
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    });

    return () => {
      cancelled = true;
      themeObserver.disconnect();
    };
  }, [chart, reactId, title]);

  const titleId = `boxd-flowchart-title-${reactId.replace(/[^a-zA-Z0-9]/g, '')}`;

  return (
    <figure
      className={`boxd-flowchart boxd-flowchart--${size}`}
      aria-labelledby={titleId}
      data-status={status}
    >
      <figcaption className="boxd-flowchart__caption">
        <span className="boxd-flowchart__kicker">Flow</span>
        <strong id={titleId}>{title}</strong>
        {description ? <span>{description}</span> : null}
      </figcaption>
      <div className="boxd-flowchart__viewport">
        <div className="boxd-flowchart__canvas" ref={canvasRef} />
        {status === 'loading' ? (
          <div className="boxd-flowchart__message" aria-live="polite">
            正在绘制流程图…
          </div>
        ) : null}
        {status === 'error' ? (
          <div className="boxd-flowchart__message boxd-flowchart__message--error" role="alert">
            流程图加载失败，请刷新页面重试。
          </div>
        ) : null}
      </div>
    </figure>
  );
}
