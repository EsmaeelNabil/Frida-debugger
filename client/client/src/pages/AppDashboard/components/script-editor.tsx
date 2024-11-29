import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Save } from 'lucide-react'

interface ScriptEditorProps {
    isOpen: boolean
    onClose: () => void
    value: string
    onChange: (value: string) => void
}

export function ScriptEditor({
                                 isOpen,
                                 onClose,
                                 value,
                                 onChange
                             }: ScriptEditorProps) {
    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="max-w-4xl h-[80vh]">
                <DialogHeader>
                    <DialogTitle>Script Editor</DialogTitle>
                </DialogHeader>

                <div className="flex flex-col h-full">
                    <div className="flex justify-between items-center py-2 px-4 bg-muted">
                        <div className="flex space-x-2">
                            <div className="w-3 h-3 rounded-full bg-red-500" />
                            <div className="w-3 h-3 rounded-full bg-yellow-500" />
                            <div className="w-3 h-3 rounded-full bg-green-500" />
                        </div>
                        <Button size="sm" onClick={onClose}>
                            <Save className="h-4 w-4 mr-2" />
                            Save Changes
                        </Button>
                    </div>

                    <ScrollArea className="flex-1 p-4">
            <textarea
                value={value}
                onChange={(e) => onChange(e.target.value)}
                className="w-full h-full min-h-[400px] font-mono text-sm focus:outline-none"
                spellCheck="false"
            />
                    </ScrollArea>
                </div>
            </DialogContent>
        </Dialog>
    )
}