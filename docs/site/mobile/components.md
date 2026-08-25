# 参考组件与 API

本页的组件是文档级 React Native 参考实现，便于复制到你的 App。它们没有作为 `@boxd/mobile` 发布，也不承诺独立版本兼容；数据应来自你的应用后端。

## `BoxStatusCard`

展示名称、runtime、状态和更新时间，并把过渡态与故障态以不同可访问标签表达。

```tsx
import { Pressable, StyleSheet, Text, View } from 'react-native';

type BoxStatus = 'creating' | 'idle' | 'running' | 'paused' | 'error' | 'deleted';

export interface BoxStatusCardProps {
  id: string;
  name?: string | null;
  runtime: string;
  status: BoxStatus;
  updatedAt: number;
  onPress?: (id: string) => void;
  disabled?: boolean;
}

const statusLabel: Record<BoxStatus, string> = {
  creating: '正在创建', idle: '就绪', running: '运行中',
  paused: '已暂停', error: '异常', deleted: '已删除',
};

export function BoxStatusCard(props: BoxStatusCardProps) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`${props.name ?? props.id}，${statusLabel[props.status]}`}
      disabled={props.disabled}
      onPress={() => props.onPress?.(props.id)}
      style={({ pressed }) => [styles.card, pressed && styles.pressed]}
    >
      <View style={styles.row}>
        <Text style={styles.title}>{props.name ?? '未命名沙盒'}</Text>
        <Text style={styles.badge}>{statusLabel[props.status]}</Text>
      </View>
      <Text style={styles.meta}>{props.runtime} · {props.id.slice(0, 8)}</Text>
      <Text style={styles.time}>{new Date(props.updatedAt).toLocaleString()}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  card: { padding: 16, borderRadius: 16, backgroundColor: '#0B1728', gap: 8 },
  pressed: { opacity: 0.82 },
  row: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  title: { color: '#F3F7FC', fontSize: 17, fontWeight: '700', flex: 1 },
  badge: { color: '#46E6CE', fontSize: 12, fontWeight: '700' },
  meta: { color: '#9AAAC0', fontFamily: 'monospace' },
  time: { color: '#718198', fontSize: 12 },
});
```

### Props

| 属性 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `string` | 是 | Box identity；只用于展示缩写和事件回调 |
| `name` | `string \| null` | 否 | 可读名称 |
| `runtime` | `string` | 是 | 当前 runtime |
| `status` | `BoxStatus` | 是 | 六种固定状态之一 |
| `updatedAt` | `number` | 是 | App 后端归一化后的 epoch milliseconds |
| `onPress` | `(id) => void` | 否 | 打开详情 |
| `disabled` | `boolean` | 否 | 禁止交互并交由 Pressable 表达状态 |

## `RunEventList`

将持久化的 SSE 事件渲染为稳定时间线。只展示已知 event type；未知类型保留占位以便协议升级。

```tsx
import { FlatList, Text, View } from 'react-native';

export interface RunEventItem {
  id: string;       // 建议 `${runId}:${sequence}`
  sequence: number;
  type: 'run_start' | 'text' | 'thinking' | 'tool' | 'tool_result' | 'stats' | 'done' | 'error';
  text?: string;
  toolName?: string;
}

export interface RunEventListProps {
  events: readonly RunEventItem[];
  running?: boolean;
  onEndReached?: () => void;
  emptyLabel?: string;
}

export function RunEventList({ events, running, onEndReached, emptyLabel }: RunEventListProps) {
  return (
    <FlatList
      data={[...events].sort((a, b) => a.sequence - b.sequence)}
      keyExtractor={(item) => item.id}
      onEndReached={onEndReached}
      ListEmptyComponent={<Text>{emptyLabel ?? (running ? '等待事件…' : '暂无事件')}</Text>}
      renderItem={({ item }) => (
        <View accessibilityLabel={`事件 ${item.sequence}，${item.type}`}>
          <Text>{item.type === 'tool' ? `工具：${item.toolName}` : item.type}</Text>
          {item.text ? <Text selectable>{item.text}</Text> : null}
        </View>
      )}
    />
  );
}
```

### Props

| 属性 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `events` | `readonly RunEventItem[]` | — | 以 sequence 排序并用稳定 id 去重 |
| `running` | `boolean` | `false` | 控制空态文案，不隐式发起请求 |
| `onEndReached` | `() => void` | — | 加载更早/更多历史 |
| `emptyLabel` | `string` | 自动 | 自定义空态 |

## `SandboxActions`

根据 Box 状态只开放合法动作，并在 destructive action 前要求调用方确认。

```tsx
import { Button, View } from 'react-native';

export interface SandboxActionsProps {
  status: BoxStatus;
  busy?: boolean;
  onPause: () => void;
  onResume: () => void;
  onDelete: () => void;
}

export function SandboxActions(props: SandboxActionsProps) {
  const canPause = props.status === 'idle';
  const canResume = props.status === 'paused';
  const canDelete = !['creating', 'deleted'].includes(props.status);

  return (
    <View style={{ gap: 12 }}>
      {canPause ? <Button title="暂停" disabled={props.busy} onPress={props.onPause} /> : null}
      {canResume ? <Button title="恢复" disabled={props.busy} onPress={props.onResume} /> : null}
      {canDelete ? <Button title="删除沙盒" color="#D94B55" disabled={props.busy} onPress={props.onDelete} /> : null}
    </View>
  );
}
```

### Props 与事件

| 属性 | 类型 | 说明 |
| --- | --- | --- |
| `status` | `BoxStatus` | 决定显示 pause/resume/delete 哪些动作 |
| `busy` | `boolean` | mutation 期间禁用所有动作 |
| `onPause` | `() => void` | 调用方执行 pause mutation |
| `onResume` | `() => void` | 调用方执行 resume mutation |
| `onDelete` | `() => void` | 调用方先二次确认，再执行 delete |

组件本身不发送网络请求，也不保存 key。这样可以在 UI、授权和 API client 之间保持清晰边界。
