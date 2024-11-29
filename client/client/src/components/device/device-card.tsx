import {useState} from 'react'
import {useNavigate} from 'react-router-dom'
import {Card, CardHeader, CardContent} from '@/components/ui/card'
import {Badge} from '@/components/ui/badge'
import {Smartphone, Laptop} from 'lucide-react'
import type {Device} from '@/types'

interface DeviceCardProps {
    device: Device
}

export function DeviceCard({device}: DeviceCardProps) {
    const navigate = useNavigate()
    const [isHovered, setIsHovered] = useState(false)
    console.log('device', device)

    return (
        <Card
            className={`
        transition-transform duration-300 cursor-pointer
        ${isHovered ? 'scale-105' : ''}
      `}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            onClick={() => navigate(`/device/${device.impl.id}`)}
        >
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <h3 className="font-semibold text-lg">{device.impl.name}</h3>
                {device.impl.type === 'usb' ? (
                    <Smartphone className="h-6 w-6"/>
                ) : (
                    <Laptop className="h-6 w-6"/>
                )}
            </CardHeader>
            <CardContent>
                <div className="flex gap-2">
                    <Badge>{device.impl.id}</Badge>
                    <Badge variant={device.impl.type === 'usb' ? 'default' : 'secondary'}>
                        {device.impl.type}
                    </Badge>
                </div>
            </CardContent>
        </Card>
    )
}