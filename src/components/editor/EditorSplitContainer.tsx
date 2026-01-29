import { useEditorStore } from '@/stores/editorStore'
import { EditorGroup } from './EditorGroup'
import { HorizontalGroup, VerticalGroup, FlexPanel } from '@/components/layout/FlexLayout'

export function EditorSplitContainer() {
  const { editorGroups, closeEditorGroup, splitGroup } = useEditorStore()

  const handleSplit = (groupId: string, orientation: 'horizontal' | 'vertical') => {
    splitGroup(groupId, orientation)
  }

  if (editorGroups.length === 1) {
    const group = editorGroups[0]
    return (
      <div className="h-full w-full">
        <EditorGroup
          key={group.id}
          groupId={group.id}
          onSplit={(orientation) => handleSplit(group.id, orientation)}
        />
      </div>
    )
  }

  const isHorizontalLayout = editorGroups.every((g) => g.orientation === 'horizontal')
  const direction = isHorizontalLayout ? 'horizontal' : 'vertical'

  const Wrapper = direction === 'horizontal' ? HorizontalGroup : VerticalGroup

  return (
    <Wrapper className="h-full w-full">
      {editorGroups.map((group, index) => (
        <>
          <FlexPanel key={group.id} className="min-w-0 min-h-0">
            <EditorGroup
              groupId={group.id}
              onSplit={(orientation) => handleSplit(group.id, orientation)}
              onClose={() => closeEditorGroup(group.id)}
            />
          </FlexPanel>
          {index < editorGroups.length - 1 && (
            <div className="bg-[#1e1e1e] hover:bg-[#007acc] transition-colors shrink-0 cursor-col-resize" style={{ width: '4px' }} />
          )}
        </>
      ))}
    </Wrapper>
  )
}
