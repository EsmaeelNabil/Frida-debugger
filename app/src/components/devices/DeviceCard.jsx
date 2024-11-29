import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardHeader, CardContent } from '@/components/ui/card.jsx';
import { Badge } from '@/components/ui/badge.jsx';
import { Smartphone, Laptop } from 'lucide-react';

export default function DeviceCard({ device }) {
    const navigate = useNavigate();
    const [isHovered, setIsHovered] = useState(false);

    const handleClick = () => {
        navigate(`/device/${device.id}`);
    };

    return (
        <Card
            className={`
        transition-transform duration-300 cursor-pointer
        ${isHovered ? 'scale-105' : ''}
      `}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            onClick={handleClick}
        >
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <h3 className="font-semibold text-lg">{device.name}</h3>
                {device.type === 'usb' ? (
                    <Smartphone className="h-6 w-6" />
                ) : (
                    <Laptop className="h-6 w-6" />
                )}
            </CardHeader>
            <CardContent>
                <div className="flex gap-2">
                    <Badge>{device.id}</Badge>
                    <Badge variant={device.status === 'online' ? 'success' : 'secondary'}>
                        {device.status}
                    </Badge>
                </div>
            </CardContent>
        </Card>
    );
}