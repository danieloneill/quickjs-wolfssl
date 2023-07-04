var curImage = -1;

function openGallery(imgidx) {
	const iv = document.getElementById('imageViewer');
	const il = document.getElementById('imageLabel');
	const fi = document.getElementById('focusImage');
	showLoader();
	fi.src = images[imgidx].path;
	il.textContent = images[imgidx].name;
	il.style.visibility = 'visible';
	iv.style.opacity = 1;
	iv.style.visibility = 'visible';
	curImage = imgidx;
}

function closeGallery() {
	const iv = document.getElementById('imageViewer');
	const il = document.getElementById('imageLabel');
	const fi = document.getElementById('focusImage');
	fi.src = 'data:image/jpg;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAQCAYAAAFcjQ7rAAAABGdBTUEAALGPC/xhBQAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAK5JREFUKM9tkTEOwyAMRZ8RbKygHiFS7n+UXALULVsUuUPtyknDYplvv28DVUtLAFQtIwFI1XICrwS8gSlVC4AmQAFJgFxuvGYADejZlA5M4MzW81chfM9wRrOqSdXSqhatWobPpgbswCKmdG+7M0gx2eUQZ2DWtr8lkeGczSLmvCZgMaav4yP1XY4ZPSawWsQat2xJD8LFKoeHuc+Av96TILYncQYC7UfMD0L8Qj5z9ENPvhMP+QAAAABJRU5ErkJggg==';
	iv.style.opacity = 0;
	iv.style.visibility = 'hidden';
	il.style.visibility = 'hidden';
}

function galleryPrev() {
	let idx = curImage-1;
	if( idx < 0 )
		idx = images.length-1;
	openGallery(idx);
}

function galleryNext() {
	let idx = curImage+1;
	if( idx >= images.length )
		idx = 0;
	openGallery(idx);
}

function showLoader() {
	const li = document.getElementById('loader');
	li.style.visibility = 'visible';
	li.style.opacity = 1;
}

function hideLoader() {
	const li = document.getElementById('loader');
	li.style.visibility = 'hidden';
	li.style.opacity = 0;
}

function initKeys() {
	const iv = document.getElementById('imageViewer');
	const fi = document.getElementById('focusImage');

	fi.addEventListener('load', (e) => { hideLoader(); });
	
	window.addEventListener(
		"keydown",
		(event) => {
			if( iv.style.visibility !== 'visible' )
				return;
			if( event.defaultPrevented )
				return;

			const keyName = event.key;
			//console.log("Key: "+keyName);

			if( keyName === "Escape" )
				closeGallery();
			else if( keyName === "ArrowLeft" )
				galleryPrev();
			else if( keyName === "ArrowRight" )
				galleryNext();
		},
		false
	);
}

initKeys();
console.log("gallery.js loaded.");
