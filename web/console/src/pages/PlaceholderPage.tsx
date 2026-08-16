import { Typography } from 'antd';
import { UnsupportedCapability } from '../components/AsyncState';
import { TerminalPlaceholder } from '../components/TerminalPlaceholder';

export function PlaceholderPage({ title, feature }: { title: string; feature: string }) { return <main><Typography.Title level={2}>{title}</Typography.Title><UnsupportedCapability feature={feature} />{title === 'Boxes' && <section className="terminal"><TerminalPlaceholder /></section>}</main>; }
