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

function initGallery() {
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

	const icons = document.querySelectorAll('.galleryIcon');
	for( const i of icons )
	{
		i.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" height="1em" viewBox="0 0 576 512"><!--! Font Awesome Free 6.4.0 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license (Commercial License) Copyright 2023 Fonticons, Inc. --><path d="M160 80H512c8.8 0 16 7.2 16 16V320c0 8.8-7.2 16-16 16H490.8L388.1 178.9c-4.4-6.8-12-10.9-20.1-10.9s-15.7 4.1-20.1 10.9l-52.2 79.8-12.4-16.9c-4.5-6.2-11.7-9.8-19.4-9.8s-14.8 3.6-19.4 9.8L175.6 336H160c-8.8 0-16-7.2-16-16V96c0-8.8 7.2-16 16-16zM96 96V320c0 35.3 28.7 64 64 64H512c35.3 0 64-28.7 64-64V96c0-35.3-28.7-64-64-64H160c-35.3 0-64 28.7-64 64zM48 120c0-13.3-10.7-24-24-24S0 106.7 0 120V344c0 75.1 60.9 136 136 136H456c13.3 0 24-10.7 24-24s-10.7-24-24-24H136c-48.6 0-88-39.4-88-88V120zm208 24a32 32 0 1 0 -64 0 32 32 0 1 0 64 0z"/></svg>';
	}
}

window.addEventListener('load', (e) => {
	initGallery();
	console.log("gallery.js loaded.");
});
