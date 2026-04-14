// face-verify.js
let video = null;
let canvas = null;
let stream = null;

// ফেস মডেল লোড করুন
async function loadFaceModels() {
    const modelsPath = '/models';
    await faceapi.nets.tinyFaceDetector.loadFromUri(modelsPath);
    await faceapi.nets.faceLandmark68Net.loadFromUri(modelsPath);
    await faceapi.nets.faceRecognitionNet.loadFromUri(modelsPath);
    console.log('✅ ফেস মডেল লোডেড');
}

// ওয়েবক্যাম শুরু করুন
async function startWebcam(videoElementId) {
    video = document.getElementById(videoElementId);
    stream = await navigator.mediaDevices.getUserMedia({ video: true });
    video.srcObject = stream;
    return new Promise((resolve) => {
        video.onloadedmetadata = () => {
            video.play();
            resolve();
        };
    });
}

// ওয়েবক্যাম বন্ধ করুন
function stopWebcam() {
    if (stream) {
        stream.getTracks().forEach(track => track.stop());
        stream = null;
    }
    if (video) {
        video.srcObject = null;
    }
}

// ফেস ডিস্ক্রিপ্টর বের করুন
async function getFaceDescriptor() {
    if (!video) {
        throw new Error('ওয়েবক্যাম শুরু হয়নি');
    }
    
    const detection = await faceapi.detectSingleFace(video, new faceapi.TinyFaceDetectorOptions())
        .withFaceLandmarks()
        .withFaceDescriptor();
    
    if (!detection) {
        throw new Error('মুখ শনাক্ত করা যায়নি! ভালো আলোতে সোজা হয়ে বসুন।');
    }
    
    return Array.from(detection.descriptor);
}

// ফেস নিবন্ধন করুন
async function registerFace() {
    try {
        const descriptor = await getFaceDescriptor();
        const token = localStorage.getItem('authToken');
        
        const res = await fetch('/api/save-face-descriptor', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ descriptor })
        });
        
        const data = await res.json();
        if (data.success) {
            alert('✅ ফেস নিবন্ধন সম্পন্ন হয়েছে!');
            return true;
        } else {
            alert('❌ নিবন্ধন ব্যর্থ: ' + data.error);
            return false;
        }
    } catch (err) {
        alert('❌ ত্রুটি: ' + err.message);
        return false;
    }
}

// ফেস ভেরিফিকেশন করুন
async function verifyFace() {
    try {
        const descriptor = await getFaceDescriptor();
        const token = localStorage.getItem('authToken');
        
        const res = await fetch('/api/match-face', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ descriptor })
        });
        
        const data = await res.json();
        if (data.success) {
            alert(`✅ ভেরিফিকেশন সফল! (মিলের হার: ${(1 - data.distance).toFixed(2)}%)`);
            return true;
        } else {
            alert('❌ ভেরিফিকেশন ব্যর্থ! আপনার মুখ মেলানো যায়নি।');
            return false;
        }
    } catch (err) {
        alert('❌ ত্রুটি: ' + err.message);
        return false;
    }
}

// ফেস ভেরিফিকেশন মডাল তৈরি করুন
function createFaceModal(title, onSuccess, onCancel) {
    // মডাল HTML তৈরি করুন
    const modalHtml = `
        <div id="faceModal" class="fixed inset-0 bg-black/70 backdrop-blur z-50 flex items-center justify-center p-4">
            <div class="bg-gray-800 rounded-2xl p-6 max-w-md w-full border border-gray-700">
                <h3 class="text-xl font-bold text-white mb-4">${title}</h3>
                <div class="relative">
                    <video id="faceVideo" autoplay playsinline class="w-full rounded-lg bg-black"></video>
                    <div id="faceStatus" class="absolute bottom-2 left-0 right-0 text-center text-white text-sm bg-black/50 p-1">ওয়েবক্যাম চালু হচ্ছে...</div>
                </div>
                <div class="flex gap-3 mt-4">
                    <button id="faceConfirmBtn" class="flex-1 bg-green-600 text-white font-bold py-2 rounded-lg hover:bg-green-700 transition">নিশ্চিত করুন</button>
                    <button id="faceCancelBtn" class="flex-1 bg-gray-600 text-white font-bold py-2 rounded-lg hover:bg-gray-700 transition">বাতিল</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    
    const modal = document.getElementById('faceModal');
    const video = document.getElementById('faceVideo');
    const statusDiv = document.getElementById('faceStatus');
    
    // ওয়েবক্যাম শুরু করুন
    navigator.mediaDevices.getUserMedia({ video: true })
        .then(stream => {
            video.srcObject = stream;
            video.onloadedmetadata = () => {
                video.play();
                statusDiv.innerText = 'মুখ ক্যামেরার সামনে রাখুন';
            };
        })
        .catch(err => {
            statusDiv.innerText = 'ক্যামেরা অ্যাক্সেস দেওয়া হয়নি';
            console.error(err);
        });
    
    // নিশ্চিত বাটন
    document.getElementById('faceConfirmBtn').onclick = async () => {
        // ফ্রেম ক্যাপচার করুন
        const canvas = document.createElement('canvas');
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0);
        
        // ভিডিও স্ট্রিম বন্ধ করুন
        if (video.srcObject) {
            video.srcObject.getTracks().forEach(track => track.stop());
        }
        
        modal.remove();
        await onSuccess();
    };
    
    // বাতিল বাটন
    document.getElementById('faceCancelBtn').onclick = () => {
        if (video.srcObject) {
            video.srcObject.getTracks().forEach(track => track.stop());
        }
        modal.remove();
        if (onCancel) onCancel();
    };
}