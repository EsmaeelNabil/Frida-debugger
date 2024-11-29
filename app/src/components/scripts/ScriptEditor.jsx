import {useState, useCallback} from 'react';
import Editor from 'react-simple-code-editor';
import {highlight, languages} from 'prismjs';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog.jsx';
import {Button} from '@/components/ui/button.jsx';
import {Save} from 'lucide-react';

export default function ScriptEditor({
                                         isOpen,
                                         onClose,
                                         initialCode,
                                         onSave,
                                     }) {
    const [code, setCode] = useState(initialCode);

    const handleSave = useCallback(() => {
        onSave(code);
        onClose();
    }, [code, onSave, onClose]);

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="sm:max-w-2xl">
                <DialogHeader>
                    <DialogTitle>Script Editor</DialogTitle>
                </DialogHeader>

                <div className="border rounded-lg overflow-hidden bg-white">
                    <div className="bg-gray-100 px-4 py-2 border-b">
                        <div className="flex justify-between items-center">
                            <div className="flex space-x-2">
                                <div className="w-3 h-3 rounded-full bg-red-400"/>
                                <div className="w-3 h-3 rounded-full bg-yellow-400"/>
                                <div className="w-3 h-3 rounded-full bg-green-400"/>
                            </div>
                            <Button
                                size="sm"
                                onClick={handleSave}
                                className="flex items-center gap-2"
                            >
                                <Save className="h-4 w-4"/>
                                Save Changes
                            </Button>
                        </div>
                    </div>

                    <Editor
                        value={code}
                        onValueChange={setCode}
                        highlight={code => highlight(code, languages.javascript)}
                        padding={16}
                        style={{
                            fontFamily: '"Fira Code", monospace',
                            fontSize: 14,
                            minHeight: '400px',
                        }}
                        className="min-h-[400px] focus:outline-none"
                    />
                </div>
            </DialogContent>
        </Dialog>
    );
}