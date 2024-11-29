// src/App.tsx
import { BrowserRouter as Router } from 'react-router-dom'
import { Toaster } from '@/components/ui/toaster'
import { SocketProvider } from './context/SocketContext'
import AppRoutes from './routes'

function App() {
    return (
        <SocketProvider>
            <Router>
                <AppRoutes />
                <Toaster />
            </Router>
        </SocketProvider>
    )
}

export default App